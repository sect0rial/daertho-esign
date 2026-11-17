"""PDF engine for E-Sign — pure functions, no storage.

  * normalize_upload()  PDF / PNG / JPEG / DOCX / DOC / ODT / RTF  ->  a normalized PDF whose page geometry equals
                        what is displayed (page /Rotate baked into the content, mediabox = cropbox), plus page sizes.
                        Word-processor files are converted by headless LibreOffice first (office_to_pdf()), then go
                        through exactly the same PDF checks as a PDF upload.
  * render_page()       one page -> PNG (pypdfium2) for the field editor and the signer view.
  * flatten()           stamp signatures / initials / text / checkmarks onto pages (reportlab overlay merged
                        with pypdf). Field boxes are fractions of the displayed page, origin top-left.
  * certificate()       the Certificate of Completion (reportlab platypus; paginates itself).
  * combine()           concatenate PDFs (documents in order + certificate).

Libraries are permissively licensed (pypdf BSD, reportlab BSD, pypdfium2 Apache/BSD, Pillow HPND) — PyMuPDF is
deliberately avoided (AGPL).
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import unicodedata
import threading
import zipfile
from pathlib import Path
from typing import Optional

# PDFium is NOT thread-safe and FastAPI runs sync endpoints in a threadpool: every pypdfium2 call goes through this.
_PDFIUM_LOCK = threading.Lock()

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_STAMP_BYTES = 600 * 1024          # one adopted signature / text stamp image
_MAX_STAMP_PX = 2400
MAX_PAGES_PER_FILE = 200
MAX_PAGE_PT, MIN_PAGE_PT = 5000.0, 36.0  # longest side ~69 in (A0 is 3370 pt); shortest 0.5 in
MAX_RENDER_PIXELS = 16_000_000           # pixel budget for one rendered page image
MAX_IMAGE_PIXELS = 60_000_000            # decoded size of an uploaded image
MAX_STAMP_PIXELS = 8_000_000             # decoded size of a signature / text stamp
_IMG_LONG_EDGE = 2480                    # scanned images are stored at most A4 @ 300 dpi


from . import brand as _brand


def _accent() -> str:
    """The brand accent for the certificate's headings (a #rrggbb colour), else the default ink-violet."""
    try:
        if hasattr(_brand, "accent"):
            v = _brand.accent() or ""
        elif hasattr(_brand, "as_dict"):
            v = (_brand.as_dict() or {}).get("accent") or ""
        else:
            v = ""
    except Exception:
        v = ""
    return v if re.fullmatch(r"#[0-9a-fA-F]{6}", v or "") else "#3b2e8c"


def _seal_cn(subject: str) -> str:
    """'Common Name: X, Organization: Y' (asn1crypto human_friendly) -> X."""
    m = re.search(r"Common Name: ([^,;]+)", subject or "")
    return m.group(1).strip() if m else ""


class PdfError(ValueError):
    """A user-facing problem with an uploaded file or stamp (message is safe to show)."""


def sha256(b: bytes) -> str:
    return hashlib.sha256(b or b"").hexdigest()


def _rl_setup():
    """No ASCII85 wrapping of binary streams (keeps generated PDFs ~25% smaller)."""
    try:
        from reportlab import rl_config
        rl_config.useA85 = 0
    except Exception:
        pass


# ------------------------------------------------------------------------------------------------- upload
def _is_pdf(b: bytes) -> bool:
    return b[:1024].lstrip().startswith(b"%PDF") or b"%PDF-" in b[:1024]


def _is_png(b: bytes) -> bool:
    return b[:8] == b"\x89PNG\r\n\x1a\n"


def _is_jpeg(b: bytes) -> bool:
    return b[:3] == b"\xff\xd8\xff"


def _open_image_checked(data: bytes, max_pixels: int, what: str = "image"):
    """Open an image, checking its declared size BEFORE decoding (no decompression bombs)."""
    from PIL import Image
    try:
        im = Image.open(io.BytesIO(data))          # lazy: reads the header only
        w, h = im.size
    except Exception:
        raise PdfError(f"That {what} could not be read.")
    if w < 2 or h < 2 or max(w, h) > 20000 or w * h > max_pixels:
        raise PdfError(f"That {what} is too large ({w}×{h} pixels).")
    try:
        im.load()
    except Exception:
        raise PdfError(f"That {what} could not be read.")
    return im


def _image_to_pdf(data: bytes) -> bytes:
    """One image -> one-page PDF (width 595pt, height by aspect ratio; EXIF orientation applied; long edge capped
    at 2480 px; JPEG stays JPEG so photos stay compact)."""
    from PIL import Image, ImageOps
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    _rl_setup()
    was_jpeg = _is_jpeg(data)
    im = _open_image_checked(data, MAX_IMAGE_PIXELS, "image")
    try:
        im = ImageOps.exif_transpose(im)
    except Exception:
        pass
    if im.mode.startswith("I;16"):
        im = im.convert("I")
    if im.mode == "I":
        im = im.point(lambda v: v * (1 / 256.0)).convert("L")
    if im.mode not in ("RGB", "L"):
        bg = Image.new("RGB", im.size, (255, 255, 255))
        rgba = im.convert("RGBA")
        bg.paste(rgba, mask=rgba.split()[-1])
        im = bg
    if max(im.size) > _IMG_LONG_EDGE:
        im.thumbnail((_IMG_LONG_EDGE, _IMG_LONG_EDGE))
    w_px, h_px = im.size
    if w_px < 10 or h_px < 10:
        raise PdfError("That image is too small.")
    pw = 595.0
    ph = pw * h_px / w_px
    if ph > MAX_PAGE_PT:                      # very tall image: fit the long side instead
        ph = MAX_PAGE_PT
        pw = ph * w_px / h_px
    if pw < MIN_PAGE_PT or ph < MIN_PAGE_PT:
        raise PdfError("That image has an unusual shape — crop it and try again.")
    enc = io.BytesIO()
    if was_jpeg:
        im.convert("RGB").save(enc, "JPEG", quality=88)
    else:
        im.save(enc, "PNG")
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(pw, ph))
    c.drawImage(ImageReader(io.BytesIO(enc.getvalue())), 0, 0, width=pw, height=ph)
    c.showPage()
    c.save()
    return buf.getvalue()


def _norm_box(box):
    """(left, bottom, width, height) of a PDF box with inverted corners normalised."""
    x1, y1, x2, y2 = (float(v) for v in (box.left, box.bottom, box.right, box.top))
    return min(x1, x2), min(y1, y2), abs(x2 - x1), abs(y2 - y1)


def page_sizes(pdf: bytes) -> list:
    from pypdf import PdfReader
    r = PdfReader(io.BytesIO(pdf), strict=False)
    out = []
    for p in r.pages:
        _, _, w, h = _norm_box(p.mediabox)
        out.append({"w": round(w, 2), "h": round(h, 2)})
    return out


def _trial_stamp(pdf: bytes) -> None:
    """Merge a blank overlay onto every page with the same pypdf path flatten() uses, so a document that could
    never be stamped is rejected at upload rather than failing at signing time."""
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    blanks = {}
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(pdf), strict=False))
    for pg in w.pages:
        _, _, W, H = _norm_box(pg.mediabox)
        key = (round(W, 1), round(H, 1))
        if key not in blanks:
            b = io.BytesIO()
            c = canvas.Canvas(b, pagesize=(W, H))
            c.showPage()
            c.save()
            blanks[key] = b.getvalue()
        pg.merge_page(PdfReader(io.BytesIO(blanks[key])).pages[0])
    w.write(io.BytesIO())


# ------------------------------------------------------------------------------------------------- office documents
# Word / OpenDocument / RTF uploads are converted to PDF by headless LibreOffice (the high-fidelity standard for
# contracts) and the result then goes through exactly the same PDF normalisation as a PDF upload.
#
# The document is untrusted input to a large C++ program, so:
#   * the bytes are sniffed; the converter only ever sees a positively identified DOCX / DOC / ODT / RTF, and a file
#     whose name claims one thing while its bytes are another is rejected;
#   * DOCX / ODT zip guard: entry count, total declared uncompressed size, per-entry compression ratio, encrypted
#     entries, then a full CRC-checked read within that budget (a damaged or lying archive never reaches LibreOffice);
#   * a fresh throwaway profile per conversion, pre-seeded with: macros disabled outright, links from untrusted
#     documents blocked (no linked images/objects fetched from the network or the local disk), Writer link updates
#     "never", and every proxy pointed at a dead local port so any outbound HTTP(S) fails at once;
#   * a scrubbed environment (no API keys / DSNs) whose HOME and TMPDIR are the private temp dir, removed afterwards
#     whatever happens;
#   * when the API runs as root and the unprivileged account exists (Dockerfile: esignconv), LibreOffice runs as that
#     account, so it cannot read the API process's environment (/proc/1/environ) or any root-only file;
#   * a hard wall-clock timeout that kills the whole process group, prlimit CPU / file-size caps when available, the
#     output size checked, and one conversion at a time.
OFFICE_TIMEOUT_S = 60                     # wall clock for one LibreOffice run
OFFICE_QUEUE_WAIT_S = 30                  # how long an upload waits for the converter before "busy" (keeps < proxy timeouts)
MAX_OFFICE_ZIP_ENTRIES = 3000
MAX_OFFICE_UNZIPPED = 160 * 1024 * 1024   # total declared + actually inflated size of a DOCX / ODT
MAX_PARSE_UNZIPPED = 100 * 1024 * 1024    # an Office package parsed in-process (python-docx / python-pptx / lxml), as a Strict .xlsx upload
MAX_OFFICE_RATIO = 200                    # an entry inflating more than 200:1 ...
_RATIO_MIN_BYTES = 4 * 1024 * 1024        # ... to more than 4 MB is treated as a zip bomb
_OFFICE_MAX_WRITE = 256 * 1024 * 1024     # prlimit --fsize for the converter (profile + temp + output)
_DEAD_PROXY = ("127.0.0.1", 9)            # discard port: nothing listens, so connections are refused at once
_CONVERT_SLOT = threading.BoundedSemaphore(1)
OFFICE_MAX_WAITING = 3                    # uploads allowed to queue behind the running conversion (<= 4 threads held)
_WAIT_LOCK = threading.Lock()
_WAITING = [0]
_OFFICE_MAX_AS = int(os.environ.get("ESIGN_CONVERT_MAX_AS", str(3 * 1024 ** 3)))   # address-space cap
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

OFFICE_FORMATS = {
    "docx": {"mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "ext": ".docx",
             "label": "Word document", "short": "Word"},
    "doc": {"mime": "application/msword", "ext": ".doc", "label": "Word 97–2003 document", "short": "Word"},
    "odt": {"mime": "application/vnd.oasis.opendocument.text", "ext": ".odt", "label": "OpenDocument text file",
            "short": "OpenDocument"},
    "rtf": {"mime": "application/rtf", "ext": ".rtf", "label": "RTF document", "short": "RTF"},
}
# Presentations can be converted the same way (presentation_to_pdf, for library use; envelope uploads still refuse
# them): same sandboxed LibreOffice run, with Impress's PDF export (needs libreoffice-impress-nogui in the image).
SLIDE_FORMATS = {
    "pptx": {"mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation", "ext": ".pptx",
             "label": "PowerPoint presentation", "short": "PowerPoint", "export": "impress_pdf_Export"},
    "ppt": {"mime": "application/vnd.ms-powerpoint", "ext": ".ppt", "label": "PowerPoint 97–2003 presentation",
            "short": "PowerPoint", "export": "impress_pdf_Export"},
    "odp": {"mime": "application/vnd.oasis.opendocument.presentation", "ext": ".odp",
            "label": "OpenDocument presentation", "short": "OpenDocument", "export": "impress_pdf_Export"},
}
WORD_EXTS = (".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm", ".rtf")
ODF_EXTS = (".odt", ".ott")
OFFICE_EXTS = WORD_EXTS + ODF_EXTS
_PDFIMG_EXTS = (".pdf", ".png", ".jpg", ".jpeg")

_MSG_DAMAGED = "That document appears to be damaged — open it in your word processor and save it again, or upload a PDF."
_MSG_BOMB = ("That document expands to far more data than a contract should when opened, so it can't be converted "
             "safely. Save it as PDF and upload that.")
_MSG_PASSWORD = "Password-protected documents aren't supported — remove the password and upload again."
_MSG_NO_SOFFICE = "Word documents can't be converted on this server — save the document as PDF and upload that."
_MSG_FAILED = ("That document couldn't be converted to PDF. If it is password-protected, remove the password; "
               "otherwise open it in your word processor, save it as PDF and upload that.")
_MSG_SPREADSHEET = "Spreadsheets aren't supported — export it as PDF and upload that."
_MSG_PRESENTATION = "Presentations aren't supported — export it as PDF and upload that."


def _ext(filename: str) -> str:
    return os.path.splitext(os.path.basename(filename or ""))[1].lower()


def _zip_guard(zf: "zipfile.ZipFile", infos: list, max_unzipped: Optional[int] = None) -> None:
    """Bounds a DOCX / ODT before anything inflates it in earnest. Raises PdfError."""
    max_unzipped = MAX_OFFICE_UNZIPPED if max_unzipped is None else max_unzipped
    if len(infos) > MAX_OFFICE_ZIP_ENTRIES:
        raise PdfError(f"That document has too many internal parts ({len(infos)}) to convert safely — save it as PDF "
                       f"and upload that.")
    total = 0
    for i in infos:
        if i.flag_bits & 0x1:
            raise PdfError(_MSG_PASSWORD)
        size = max(0, int(i.file_size))
        total += size
        if size > _RATIO_MIN_BYTES and size > MAX_OFFICE_RATIO * max(1, int(i.compress_size)):
            raise PdfError(_MSG_BOMB)
    if total > max_unzipped:
        raise PdfError(_MSG_BOMB)
    # Read everything back within the same budget: CRC-checks every entry (zipfile stops at the declared size and
    # verifies the CRC), so an archive whose headers lie about sizes is caught here, not inside LibreOffice.
    budget = max_unzipped
    try:
        for i in infos:
            if i.is_dir():
                continue
            with zf.open(i) as f:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    budget -= len(chunk)
                    if budget < 0:
                        raise PdfError(_MSG_BOMB)
    except PdfError:
        raise
    except Exception:
        raise PdfError(_MSG_DAMAGED)


def check_office_zip(data: bytes, max_unzipped: int = MAX_PARSE_UNZIPPED) -> None:
    """The same bounds for an Office package (.docx / .pptx / .potx / .xlsx) that is parsed in-process rather than
    converted: entry count, per-entry inflation ratio, total unzipped size (declared and actually inflated), no
    encrypted entries. Raises PdfError with a user-safe message. A body that is not a zip is left to the caller's
    parser to refuse. Every upload route that hands bytes to python-docx, python-pptx or an XML parser calls this
    first (the Strict .xlsx reader has its own cap), so a crafted package cannot balloon the API's memory."""
    if data[:4] != b"PK\x03\x04":
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception:
        return
    _zip_guard(zf, infos, max_unzipped)


def _zip_member(zf: "zipfile.ZipFile", name: str, cap: int) -> bytes:
    try:
        info = zf.getinfo(name)
        if info.file_size > cap or info.flag_bits & 0x1:
            return b""
        with zf.open(info) as f:
            return f.read(cap)
    except Exception:
        return b""


def _sniff_zip(data: bytes):
    """-> (fmt | None, problem | None) for a ZIP container."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception:
        return None, None
    names = {i.filename for i in infos}
    ct = _zip_member(zf, "[Content_Types].xml", 1024 * 1024)
    fmt = None
    if "word/document.xml" in names or any(k in ct for k in (b"wordprocessingml.document.main", b"ms-word.document.",
                                                             b"wordprocessingml.template.main", b"ms-word.template.")):
        fmt = "docx"
    elif "mimetype" in names:
        mt = _zip_member(zf, "mimetype", 200).strip()
        if mt in (b"application/vnd.oasis.opendocument.text", b"application/vnd.oasis.opendocument.text-template"):
            fmt = "odt"
        elif mt.startswith(b"application/vnd.oasis.opendocument.spreadsheet"):
            return None, _MSG_SPREADSHEET
        elif mt.startswith(b"application/vnd.oasis.opendocument.presentation"):
            return None, _MSG_PRESENTATION
        else:
            return None, None
    elif "xl/workbook.xml" in names or b"spreadsheetml" in ct:
        return None, _MSG_SPREADSHEET
    elif "ppt/presentation.xml" in names or b"presentationml" in ct:
        return None, _MSG_PRESENTATION
    else:
        return None, None
    _zip_guard(zf, infos)
    return fmt, None


def _sniff_ole(data: bytes):
    """-> (fmt | None, problem | None) for an OLE2 compound file (.doc, but also .xls / .ppt / .msg and
    password-protected OOXML). Stream names sit in the directory sectors as UTF-16LE."""
    def has(name: str) -> bool:
        return name.encode("utf-16-le") in data
    if has("EncryptedPackage") and has("EncryptionInfo") and not has("WordDocument"):
        return None, _MSG_PASSWORD
    if has("WordDocument"):
        return "doc", None
    if has("Workbook"):
        return None, _MSG_SPREADSHEET
    if has("PowerPoint Document"):
        return None, _MSG_PRESENTATION
    if has("__substg1.0_"):
        return None, "That is an Outlook email (.msg) — save the attachment itself and upload that."
    return None, None


def _looks_html(data: bytes) -> bool:
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return (head.startswith(b"<!doctype html") or head.startswith(b"<html") or head.startswith(b"mime-version:")
            or (head.startswith(b"<?xml") and b"<html" in head))


def detect_office_format(data: bytes, filename: str = "") -> Optional[str]:
    """Identify a word-processor upload by its BYTES. Returns "docx" | "doc" | "odt" | "rtf", or None when the bytes
    are not a supported office document (the caller then rejects the upload). Raises PdfError (user-safe) for files
    that are recognisable but unusable (damaged, encrypted, zip bomb, spreadsheet …) and for name/content mismatches.
    PDFs and images are not judged here — they never reach the converter."""
    ext = _ext(filename)
    fmt, problem = None, None
    if data[:4] == b"PK\x03\x04":
        fmt, problem = _sniff_zip(data)
    elif data[:8] == _OLE_MAGIC:
        fmt, problem = _sniff_ole(data)
    elif data[:64].lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{\\rtf"):
        fmt = "rtf"
    if fmt is None:
        if problem:
            raise PdfError(problem)
        if ext in OFFICE_EXTS:
            if _looks_html(data):
                raise PdfError("This file is really a web page saved with a Word extension — open it in Word, save it "
                               "as .docx (or PDF) and upload that.")
            what = "OpenDocument text file" if ext in ODF_EXTS else ("RTF document" if ext == ".rtf" else "Word document")
            raise PdfError(f"This file isn't a valid {what} — it may be damaged or a different kind of file. Open it "
                           f"in your word processor and save it again, or upload a PDF.")
        return None
    info = OFFICE_FORMATS[fmt]
    if ext in _PDFIMG_EXTS:
        raise PdfError(f"This file is a {info['label']}, not a {ext[1:].upper()} — its name doesn't match its "
                       f"contents. Rename it to end in {info['ext']} and upload it again.")
    if ext and (ext not in OFFICE_EXTS or (fmt == "odt") != (ext in ODF_EXTS)):
        raise PdfError(f"This file's name doesn't match its contents (it is a {info['label']}). Save it again from "
                       f"your word processor, or upload a PDF.")
    return fmt


def find_soffice() -> Optional[str]:
    """Path of the LibreOffice launcher, or None. ESIGN_SOFFICE overrides; the Docker image puts soffice on PATH."""
    cands = []
    env = (os.environ.get("ESIGN_SOFFICE") or "").strip()
    if env:
        cands.append(env)
    for n in ("soffice", "libreoffice"):
        p = shutil.which(n)
        if p:
            cands.append(p)
    cands += ["/usr/lib/libreoffice/program/soffice", "/opt/libreoffice/program/soffice",
              "/Applications/LibreOffice.app/Contents/MacOS/soffice"]
    for p in cands:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _convert_identity():
    """(uid, gid) of the unprivileged conversion account when the API runs as root, else None.
    ESIGN_CONVERT_USER names it (default esignconv, created in the Dockerfile; empty disables the drop)."""
    name = os.environ.get("ESIGN_CONVERT_USER", "esignconv").strip()
    if not name or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    try:
        import pwd
        pw = pwd.getpwnam(name)
    except Exception:
        if not _WARNED[0]:
            _WARNED[0] = True
            print(f"esign: converting documents as root — create the unprivileged '{name}' account (see the Dockerfile)")
        return None
    if pw.pw_uid == 0:
        return None
    return pw.pw_uid, pw.pw_gid


_WARNED = [False]


def _profile_xcu() -> str:
    """registrymodifications.xcu for the throwaway LibreOffice profile (names checked against officecfg's schema)."""
    host, port = _DEAD_PROXY

    def item(path, prop, value):
        return (f'<item oor:path="{path}"><prop oor:name="{prop}" oor:op="fuse"><value>{value}</value></prop></item>')
    sec, inet = "/org.openoffice.Office.Common/Security/Scripting", "/org.openoffice.Inet/Settings"
    items = [
        item(sec, "DisableMacrosExecution", "true"),          # no Basic / Python / JS macros, whatever the level
        item(sec, "MacroSecurityLevel", "3"),                 # "very high" as a second lock
        item(sec, "BlockUntrustedRefererLinks", "true"),      # no linked images / objects from untrusted documents
        item("/org.openoffice.Office.Writer/Content/Update", "Link", "0"),   # 0 = NEVER update links (1 manual, 2 always)
        item(sec, "DisableActiveContent", "true"),            # no active embedded OLE content / DDE
        item(inet, "ooInetProxyType", "2"),                   # manual proxy ...
        item(inet, "ooInetHTTPProxyName", host), item(inet, "ooInetHTTPProxyPort", str(port)),
        item(inet, "ooInetHTTPSProxyName", host), item(inet, "ooInetHTTPSProxyPort", str(port)),
        item(inet, "ooInetNoProxy", ""),                      # ... for every host: outbound fetches are refused
    ]
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<oor:items xmlns:oor="http://openoffice.org/2001/registry" '
            'xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
            + "\n".join(items) + "\n</oor:items>\n")


def _convert_env(work: str, tmp: str) -> dict:
    """A scrubbed environment: nothing from the API process (keys, DSNs) except PATH."""
    proxy = "http://%s:%d" % _DEAD_PROXY
    env = {"PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin", "HOME": work, "TMPDIR": tmp,
           "TMP": tmp, "TEMP": tmp, "XDG_CONFIG_HOME": os.path.join(work, ".config"),
           "XDG_CACHE_HOME": os.path.join(work, ".cache"), "LANG": "C.UTF-8", "SAL_USE_VCLPLUGIN": "svp"}
    for k in ("http_proxy", "https_proxy", "ftp_proxy", "all_proxy"):
        env[k] = env[k.upper()] = proxy
    env["no_proxy"] = env["NO_PROXY"] = ""
    return env


def _prlimit_path() -> Optional[str]:
    """util-linux prlimit (always present on Debian) caps the converter's CPU time and file sizes."""
    return shutil.which("prlimit")


def _spawn(cmd: list, **kw):
    """subprocess.Popen — a seam for tests."""
    return subprocess.Popen(cmd, **kw)


def _kill_group(proc) -> None:
    """soffice is a launcher that starts soffice.bin as a child: kill the whole session, not just the launcher."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def _log_tail(path: str, n: int = 300) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.path.getsize(path) - n))
            return f.read(n).decode("utf-8", "replace").replace("\n", " ").strip()
    except Exception:
        return ""


def _read_output(path: str) -> bytes:
    try:
        st = os.lstat(path)
    except OSError:
        raise PdfError(_MSG_FAILED)
    if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
        raise PdfError(_MSG_FAILED)
    if st.st_size > MAX_FILE_BYTES:
        raise PdfError("The converted PDF is larger than 25 MB — reduce the size of the images in the document (or "
                       "split it) and upload it again.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        out = f.read(MAX_FILE_BYTES + 1)
    if len(out) > MAX_FILE_BYTES or not _is_pdf(out):
        raise PdfError(_MSG_FAILED)
    return out


def detect_slide_format(data: bytes) -> Optional[str]:
    """Identify a presentation by its BYTES: "pptx" | "odp" | "ppt", or None. Zip bombs are refused (PdfError)."""
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                total = sum(i.file_size for i in infos)
                if total > _RATIO_MIN_BYTES and total > MAX_OFFICE_RATIO * max(1, len(data)):
                    raise PdfError(_MSG_BOMB)
                names = {i.filename for i in infos}
                if "ppt/presentation.xml" in names:
                    return "pptx"
                if "mimetype" in names and z.read("mimetype").strip() == b"application/vnd.oasis.opendocument.presentation":
                    return "odp"
        except zipfile.BadZipFile:
            return None
        return None
    if data[:8] == _OLE_MAGIC and "PowerPoint Document".encode("utf-16-le") in data[:2_000_000]:
        return "ppt"
    return None


def presentation_to_pdf(data: bytes, fmt: str) -> bytes:
    """PowerPoint / OpenDocument presentation → PDF, through the same sandboxed LibreOffice run as Word files."""
    if fmt not in SLIDE_FORMATS:
        raise PdfError("Upload the template as a PDF or a PowerPoint file (.pptx or .ppt).")
    return office_to_pdf(data, fmt)


def office_to_pdf(data: bytes, fmt: str) -> bytes:
    """Convert a DOCX / DOC / ODT / RTF (already identified by detect_office_format) to PDF with headless LibreOffice.
    Returns the PDF bytes (≤ 25 MB). Raises PdfError with a user-safe message on any failure."""
    if fmt not in OFFICE_FORMATS and fmt not in SLIDE_FORMATS:
        raise PdfError(_MSG_FAILED)
    if not data or len(data) > MAX_FILE_BYTES:
        raise PdfError("Files must be 25 MB or smaller.")
    soffice = find_soffice()
    if not soffice:
        raise PdfError(_MSG_NO_SOFFICE)
    # At most one conversion runs and OFFICE_MAX_WAITING wait; anyone beyond that is told 'busy' at once, so a burst
    # of uploads can't park the API's shared worker threads (each sync request holds one while it waits).
    with _WAIT_LOCK:
        if _WAITING[0] >= OFFICE_MAX_WAITING:
            raise PdfError("Another document is being converted right now — please try again in a moment.")
        _WAITING[0] += 1
    try:
        got = _CONVERT_SLOT.acquire(timeout=OFFICE_QUEUE_WAIT_S)
    finally:
        with _WAIT_LOCK:
            _WAITING[0] -= 1
    if not got:
        raise PdfError("Another document is being converted right now — please try again in a moment.")
    try:
        return _run_soffice(soffice, data, fmt)
    except PdfError:
        raise
    except Exception as e:                    # disk full, chown refused … : never a 500, always a user-safe message
        print(f"esign: document conversion failed: {repr(e)[:300]}")
        raise PdfError(_MSG_FAILED)
    finally:
        _CONVERT_SLOT.release()


def _run_soffice(soffice: str, data: bytes, fmt: str) -> bytes:
    """One LibreOffice run in a private work dir (caller holds _CONVERT_SLOT)."""
    work = None
    try:
        ident = _convert_identity()
        work = tempfile.mkdtemp(prefix="esign-conv-", dir=os.environ.get("ESIGN_CONVERT_TMP") or None)
        indir, outdir = os.path.join(work, "in"), os.path.join(work, "out")
        profile, tmp = os.path.join(work, "profile"), os.path.join(work, "tmp")
        for d in (indir, outdir, os.path.join(profile, "user"), tmp):
            os.makedirs(d, mode=0o700)
        spec = OFFICE_FORMATS.get(fmt) or SLIDE_FORMATS[fmt]
        inpath = os.path.join(indir, "input" + spec["ext"])
        with open(os.open(inpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(data)
        with open(os.path.join(profile, "user", "registrymodifications.xcu"), "w", encoding="utf-8") as f:
            f.write(_profile_xcu())
        if ident:
            for root, dirs, files in os.walk(work):
                for n in [root] + [os.path.join(root, x) for x in dirs + files]:
                    os.chown(n, ident[0], ident[1])
        cmd = [soffice, "--headless", "--invisible", "--nologo", "--nodefault", "--norestore", "--nolockcheck",
               "-env:UserInstallation=" + Path(profile).as_uri(),
               "--convert-to", "pdf:" + spec.get("export", "writer_pdf_Export"), "--outdir", outdir, inpath]
        prlimit = _prlimit_path()
        if prlimit:
            cmd = [prlimit, f"--cpu={OFFICE_TIMEOUT_S + 30}", f"--fsize={_OFFICE_MAX_WRITE}",
                   f"--as={_OFFICE_MAX_AS}", "--"] + cmd     # memory cap: a hostile document can't OOM the host
        # Output goes to a log file, not a pipe: a straggler that inherited the pipe could otherwise hold
        # communicate() open, and a document that makes LibreOffice spew warnings can't grow our memory.
        log_path = os.path.join(work, "convert.log")
        with open(log_path, "wb") as logf:
            kw = dict(stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT, cwd=work,
                      env=_convert_env(work, tmp), start_new_session=True, close_fds=True, umask=0o077)
            if ident:
                kw.update(user=ident[0], group=ident[1], extra_groups=[])
            try:
                proc = _spawn(cmd, **kw)
            except Exception as e:
                print(f"esign: could not start LibreOffice{' as uid %d' % ident[0] if ident else ''} "
                      f"(set ESIGN_CONVERT_USER= to run it as the API user): {repr(e)[:300]}")
                raise PdfError(_MSG_FAILED)
        try:
            proc.wait(timeout=OFFICE_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
            raise PdfError(f"That document took too long to convert (over {OFFICE_TIMEOUT_S} seconds). Save it as "
                           f"PDF in your word processor and upload that instead.")
        except BaseException:
            _kill_group(proc)
            raise
        _kill_group(proc)                         # stragglers of the session, if any, before the dir is removed
        if proc.returncode != 0:
            print(f"esign: LibreOffice exited {proc.returncode} converting {fmt}: {_log_tail(log_path)}")
            raise PdfError(_MSG_FAILED)
        return _read_output(os.path.join(outdir, "input.pdf"))
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)


def normalize_upload(data: bytes, filename: str = "", content_type: Optional[str] = None,
                     max_pages: int = MAX_PAGES_PER_FILE) -> dict:
    """Validate + normalize an upload. Returns {"pdf": bytes, "pages": [{"w","h"}], "kind": "pdf"|"image"|"document",
    "source_type": MIME of the original upload, "source_format": "pdf"|"png"|"jpeg"|"docx"|"doc"|"odt"|"rtf"}.
    Word-processor files are converted to PDF first and then checked exactly like an uploaded PDF.
    Raises PdfError with a user-safe message."""
    if not data:
        raise PdfError("The file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise PdfError("Files must be 25 MB or smaller.")
    if _is_png(data) or _is_jpeg(data):
        png = _is_png(data)
        out = _normalize_pdf(_image_to_pdf(data), max_pages)
        out.update(kind="image", source_type="image/png" if png else "image/jpeg", source_format="png" if png else "jpeg")
        return out
    fmt = None
    if data[:4] == b"PK\x03\x04" or data[:8] == _OLE_MAGIC or not _is_pdf(data):
        fmt = detect_office_format(data, filename)
        if fmt is None:
            raise PdfError("Upload a PDF, a Word document (.docx, .doc), an OpenDocument text (.odt), an RTF file, or "
                           "a PNG / JPEG image.")
    if fmt is None:
        out = _normalize_pdf(data, max_pages)
        out.update(kind="pdf", source_type="application/pdf", source_format="pdf")
        return out
    pdf = office_to_pdf(data, fmt)
    try:
        out = _normalize_pdf(pdf, max_pages)
    except PdfError as e:
        msg = str(e)
        raise PdfError(("The converted document" + msg[len("That PDF"):]) if msg.startswith("That PDF") else msg) from None
    out.update(kind="document", source_type=OFFICE_FORMATS[fmt]["mime"], source_format=fmt)
    return out


def _normalize_pdf(data: bytes, max_pages: int) -> dict:
    """The PDF half of normalize_upload (every upload ends up here, converted or not)."""
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import RectangleObject
    try:
        r = PdfReader(io.BytesIO(data), strict=False)
        encrypted = r.is_encrypted
    except Exception:
        raise PdfError("That PDF could not be read — it may be damaged.")
    if encrypted:
        try:
            ok = r.decrypt("")
        except Exception:
            ok = 0
        if not ok:
            raise PdfError("Password-protected PDFs aren't supported — remove the password and upload again.")
    try:
        n = len(r.pages)
    except Exception:
        raise PdfError("That PDF could not be read — it may be damaged.")
    if n == 0:
        raise PdfError("That PDF has no pages.")
    if n > max_pages:
        raise PdfError(f"That PDF has {n} pages — the limit is {max_pages}.")
    try:
        w = PdfWriter()
        for i, page in enumerate(r.pages):
            try:
                x, y, cw, ch = _norm_box(page.cropbox)          # what viewers display
                page.mediabox = RectangleObject([x, y, x + cw, y + ch])
                page.cropbox = RectangleObject([x, y, x + cw, y + ch])
            except Exception:
                pass
            try:
                if (page.get("/Rotate") or 0) % 360:
                    page.transfer_rotation_to_content()   # bake rotation: geometry == displayed orientation
            except Exception:
                pass
            _, _, pw, ph = _norm_box(page.mediabox)
            if not (MIN_PAGE_PT <= pw <= MAX_PAGE_PT and MIN_PAGE_PT <= ph <= MAX_PAGE_PT):
                raise PdfError(f"Page {i + 1} has an unusual size ({pw:.0f}×{ph:.0f} pt) — re-save the document at a "
                               f"standard paper size.")
            w.add_page(page)
        try:
            w.add_metadata({"/Producer": _brand.name()})
        except Exception:
            pass
        out = io.BytesIO()
        w.write(out)
        pdf = out.getvalue()
        _trial_stamp(pdf)
    except PdfError:
        raise
    except Exception:
        raise PdfError("That PDF couldn't be prepared for signing — try re-saving it as a standard PDF.")
    # make sure the renderer can open it too
    try:
        import pypdfium2 as pdfium
        with _PDFIUM_LOCK:
            d = pdfium.PdfDocument(pdf)
            n2 = len(d)
            d.close()
        if n2 == 0:
            raise PdfError("That PDF has no pages.")
    except PdfError:
        raise
    except Exception:
        raise PdfError("That PDF could not be rendered — try re-saving it as a standard PDF.")
    return {"pdf": pdf, "pages": page_sizes(pdf)}


# ------------------------------------------------------------------------------------------------- render
def render_page(pdf: bytes, page_index: int, scale: float = 1.5) -> bytes:
    """Render page `page_index` (0-based) to PNG bytes, within a fixed pixel budget whatever the page size."""
    import pypdfium2 as pdfium
    scale = max(0.25, min(float(scale or 1.5), 3.0))
    with _PDFIUM_LOCK:
        d = pdfium.PdfDocument(pdf)
        try:
            if page_index < 0 or page_index >= len(d):
                raise PdfError("No such page.")
            page = d[page_index]
            try:
                pw, ph = page.get_size()
                area = max(1.0, float(pw) * float(ph))
                scale = max(0.05, min(scale, (MAX_RENDER_PIXELS / area) ** 0.5))
                img = page.render(scale=scale).to_pil()
            finally:
                page.close()
        finally:
            d.close()
    out = io.BytesIO()
    img.convert("RGB").save(out, "PNG", compress_level=6)
    return out.getvalue()


# ------------------------------------------------------------------------------------------------- stamps
_DATAURL = re.compile(r"^data:image/(png|jpeg|jpg);base64,([A-Za-z0-9+/=\s]+)$", re.S)


def image_from_data_url(data_url: str, max_bytes: int = MAX_STAMP_BYTES) -> bytes:
    """Decode a data:image/png|jpeg;base64 URL -> a clean PNG (metadata stripped, size-bounded)."""
    if not isinstance(data_url, str) or len(data_url) > max_bytes * 2:
        raise PdfError("Invalid image.")
    m = _DATAURL.match(data_url.strip())
    if not m:
        raise PdfError("Signature images must be PNG or JPEG data URLs.")
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", m.group(2)), validate=True)
    except Exception:
        raise PdfError("Invalid image data.")
    if len(raw) > max_bytes:
        raise PdfError("That image is too large.")
    if not (_is_png(raw) or _is_jpeg(raw)):
        raise PdfError("Signature images must be PNG or JPEG.")
    im = _open_image_checked(raw, MAX_STAMP_PIXELS, "image")
    if max(im.size) > _MAX_STAMP_PX:
        im.thumbnail((_MAX_STAMP_PX, _MAX_STAMP_PX))
    if im.mode not in ("RGBA", "RGB", "L", "LA"):
        im = im.convert("RGBA")
    out = io.BytesIO()
    im.save(out, "PNG")
    return out.getvalue()


def latin1_ok(s: str) -> bool:
    try:
        (s or "").encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def _fit_font(c, text: str, font: str, box_w: float, box_h: float) -> float:
    from reportlab.pdfbase.pdfmetrics import stringWidth
    size = max(4.0, min(box_h * 0.62, 14.0))
    while size > 4.0 and stringWidth(text, font, size) > box_w * 0.96:
        size -= 0.5
    return size


def _draw_stamp(c, s: dict, W: float, H: float) -> None:
    from reportlab.lib.utils import ImageReader
    fx, fy, fw, fh = (float(s[k]) for k in ("x", "y", "w", "h"))
    bx, bw, bh = fx * W, fw * W, fh * H
    by = H - (fy + fh) * H
    kind = s.get("kind")
    c.saveState()
    try:
        clip = c.beginPath()
        clip.rect(bx, by, bw, bh)
        c.clipPath(clip, stroke=0, fill=0)            # nothing a signer enters can spill outside their box
        if kind == "image" and s.get("png"):
            img = ImageReader(io.BytesIO(s["png"]))
            iw, ih = img.getSize()
            if iw > 0 and ih > 0:
                k = min(bw / iw, bh / ih)
                dw, dh = iw * k, ih * k
                c.drawImage(img, bx, by + (bh - dh) / 2.0, width=dw, height=dh, mask="auto")
        elif kind == "text":
            text = (s.get("text") or "").replace("\n", " ").strip()
            if text:
                font = "Helvetica"
                size = _fit_font(c, text, font, bw, bh)
                c.setFillColorRGB(0.08, 0.08, 0.12)
                c.setFont(font, size)
                c.drawString(bx + bw * 0.02, by + (bh - size * 0.72) / 2.0, text)
        elif kind == "check" and s.get("checked"):
            size = max(6.0, min(bw, bh) * 0.9)
            c.setFillColorRGB(0.08, 0.08, 0.12)
            c.setFont("ZapfDingbats", size)
            c.drawString(bx + (bw - size * 0.8) / 2.0, by + (bh - size * 0.7) / 2.0, "4")   # ✔
    finally:
        c.restoreState()


def flatten(pdf: bytes, stamps: list) -> bytes:
    """Merge stamps onto pages. Each stamp: {page (1-based), x, y, w, h (fractions, top-left origin),
    kind: "image" (png bytes) | "text" (Latin-1 str) | "check" (checked bool)}."""
    if not stamps:
        return pdf
    from pypdf import PdfReader, PdfWriter, Transformation
    from reportlab.pdfgen import canvas
    _rl_setup()
    by_page: dict = {}
    for s in stamps:
        by_page.setdefault(int(s["page"]), []).append(s)
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(pdf), strict=False))
    for i, page in enumerate(w.pages):
        st = by_page.get(i + 1)
        if not st:
            continue
        x0, y0, W, H = _norm_box(page.mediabox)
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=(W, H))
        for s in st:
            _draw_stamp(c, s, W, H)
        c.showPage()
        c.save()
        ov = PdfReader(io.BytesIO(buf.getvalue())).pages[0]
        if x0 or y0:
            page.merge_transformed_page(ov, Transformation().translate(x0, y0))
        else:
            page.merge_page(ov)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def combine(pdfs: list) -> bytes:
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter()
    for b in pdfs:
        if b:
            w.append(PdfReader(io.BytesIO(b), strict=False))
    try:
        w.add_metadata({"/Producer": _brand.name()})
    except Exception:
        pass
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


def embed_files(pdf: bytes, files: list) -> bytes:
    """Attach [(filename, bytes)] to `pdf` as embedded files (PDF attachments panel)."""
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(pdf)))
    for name, data in files:
        w.add_attachment(name, data)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def attachments(pdf: bytes) -> dict:
    """{filename: bytes} of the PDF's embedded files (first copy of each name); {} if none / unreadable."""
    try:
        from pypdf import PdfReader
        return {k: v[0] for k, v in (PdfReader(io.BytesIO(pdf)).attachments or {}).items() if v}
    except Exception:
        return {}


def page_count(pdf: bytes) -> int:
    from pypdf import PdfReader
    return len(PdfReader(io.BytesIO(pdf), strict=False).pages)


# ------------------------------------------------------------------------------------------------- certificate
_UNI_FONT = None          # registered TTF name for broad-Unicode text, or "" when none is available
_UNI_CANDIDATES = [
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
]
_CJK_FONT = None
_RTL_FONT = None          # TTF with Arabic presentation forms + Hebrew (shaped via arabic-reshaper + python-bidi)
_RTL_CANDIDATES = [
    "/usr/share/fonts/truetype/freefont/FreeSerif.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
]


def _fonts():
    global _UNI_FONT, _CJK_FONT, _RTL_FONT
    if _UNI_FONT is None:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        _UNI_FONT = ""
        import os
        for p in _UNI_CANDIDATES:
            if os.path.exists(p):
                try:
                    pdfmetrics.registerFont(TTFont("ESignUni", p))
                    _UNI_FONT = "ESignUni"
                    break
                except Exception:
                    continue
        try:
            from reportlab.pdfbase.cidfonts import UnicodeCIDFont
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
            _CJK_FONT = "STSong-Light"
        except Exception:
            _CJK_FONT = ""
        _RTL_FONT = ""
        for p in _RTL_CANDIDATES:
            if os.path.exists(p):
                try:
                    pdfmetrics.registerFont(TTFont("ESignRTL", p))
                    _RTL_FONT = "ESignRTL"
                    break
                except Exception:
                    continue
    return _UNI_FONT, _CJK_FONT


def _has(text: str, ranges) -> bool:
    for ch in text:
        o = ord(ch)
        for a, b in ranges:
            if a <= o <= b:
                return True
    return False


_CJK = [(0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF), (0xF900, 0xFAFF), (0xFF00, 0xFFEF)]
_RTL = [(0x0590, 0x08FF), (0xFB1D, 0xFDFF), (0xFE70, 0xFEFF)]


def _rtl_visual(text: str) -> str:
    """Arabic/Hebrew -> visually ordered, contextually shaped text (presentation forms) that a plain TTF can
    draw left-to-right. Empty string when the shaping libraries are unavailable."""
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except Exception:
        return ""


def _translit(text: str) -> str:
    try:
        from anyascii import anyascii
        return anyascii(text)
    except Exception:
        return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def _mk(text) -> str:
    """Paragraph markup for arbitrary-script text, choosing a font that can draw it."""
    from xml.sax.saxutils import escape
    t = "" if text is None else str(text)
    if latin1_ok(t):
        return escape(t)
    uni, cjk = _fonts()
    if _has(t, _CJK) and cjk:
        return f'<font name="{cjk}">{escape(t)}</font>'
    if _has(t, _RTL):
        vis = _rtl_visual(t)
        if vis and _RTL_FONT:
            return f'<font name="{_RTL_FONT}">{escape(vis)}</font>'
        return escape(_translit(t)) + ' <font size="7" color="#777777">(transliterated)</font>'
    if uni:
        return f'<font name="{uni}">{escape(t)}</font>'
    return escape(_translit(t))


def _fmt_ts(ts: Optional[str]) -> str:
    if not ts:
        return "—"
    return ts.replace("T", " ").replace("Z", " UTC")


def certificate(env: dict, signature_pngs: Optional[dict] = None) -> bytes:
    """Certificate of Completion for envelope `env` (the full envelope dict). signature_pngs: rid -> PNG bytes."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage,
                                    KeepTogether)
    _fonts()
    _rl_setup()
    signature_pngs = signature_pngs or {}
    ink = colors.HexColor("#1a1a2e")
    acc = colors.HexColor(_accent())
    bn = _brand.name()
    mut = colors.HexColor("#555566")
    line = colors.HexColor("#d9d7e6")
    H1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=17, textColor=acc, spaceAfter=2, leading=21)
    H2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, textColor=acc, spaceBefore=10, spaceAfter=4)
    P = ParagraphStyle("p", fontName="Helvetica", fontSize=8.6, textColor=ink, leading=11)
    S = ParagraphStyle("s", fontName="Helvetica", fontSize=7.4, textColor=mut, leading=9.4)
    M = ParagraphStyle("m", fontName="Courier", fontSize=7, textColor=ink, leading=8.6)
    K = ParagraphStyle("k", fontName="Helvetica-Bold", fontSize=8, textColor=mut, leading=10)

    def kv(rows):
        t = Table([[Paragraph(k, K), Paragraph(v, P)] for k, v in rows], colWidths=[38 * mm, 135 * mm])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                               ("TOPPADDING", (0, 0), (-1, -1), 1)]))
        return t

    status = env.get("status") or ""
    heading = {"completed": "Certificate of Completion", "declined": "Envelope Record — Declined",
               "voided": "Envelope Record — Voided", "expired": "Envelope Record — Expired"}.get(
        status, "Envelope Status Report — In Progress")
    sub = (f"{_mk(bn)} · electronic signature record" if status == "completed" else
           f"{_mk(bn)} · record of this envelope as it stands — it has NOT been completed by every recipient")
    story = [Paragraph(heading, H1), Paragraph(sub, S), Spacer(1, 6)]
    docs = env.get("documents") or []
    total_pages = sum(int(d.get("page_count") or 0) for d in docs)
    story.append(kv([
        ("Envelope ID", f'<font name="Courier">{_mk(env.get("id"))}</font>'),
        ("Subject", _mk(env.get("title"))),
        ("Status", _mk((env.get("status") or "").capitalize())),
        ("Sender", _mk(env.get("sender_name") or env.get("owner"))),
        ("Created", _fmt_ts(env.get("created_at"))),
        ("Sent", _fmt_ts(env.get("sent_at"))),
        ("Completed", _fmt_ts(env.get("completed_at"))),
        ("Signing order", _mk((env.get("signing_order") or "sequential").capitalize())),
        ("Documents", f"{len(docs)} document(s), {total_pages} page(s)"),
    ]))

    story.append(Paragraph("Documents", H2))
    drows = [[Paragraph("Name", K), Paragraph("Pages", K), Paragraph("SHA-256 of original as uploaded", K)]]
    for d in sorted(docs, key=lambda x: x.get("order", 0)):
        conv = (f' <font size="7" color="#777777">(converted to PDF from {d["source_format"].upper()} on upload)</font>'
                if d.get("source_format") in OFFICE_FORMATS else "")
        hashes = d.get("sha256_original") or ""
        if d.get("sha256_converted"):             # the PDF the signers actually saw (re-conversion won't reproduce it)
            hashes += f'<br/><font size="7" color="#777777">PDF signers saw:</font> {d["sha256_converted"]}'
        drows.append([Paragraph(_mk(d.get("name")) + conv, P), Paragraph(str(d.get("page_count") or ""), P),
                      Paragraph(hashes, M)])
    dt = Table(drows, colWidths=[62 * mm, 14 * mm, 97 * mm], repeatRows=1)
    dt.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, 0), 0.6, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story.append(dt)

    story.append(Paragraph("Recipients", H2))
    role_lbl = {"signer": "Needs to sign", "cc": "Receives a copy", "viewer": "Needs to view"}
    for r in sorted(env.get("recipients") or [], key=lambda x: (x.get("routing_order", 1), x.get("name", ""))):
        rows = [
            ("Recipient", f'<b>{_mk(r.get("name"))}</b> · {_mk(r.get("email"))}'),
            ("Role", f'{role_lbl.get(r.get("role"), r.get("role"))} · routing order {r.get("routing_order")}'),
            ("Status", _mk("Reviewed" if (r.get("role") == "viewer" and r.get("status") == "signed")
                           else (r.get("status") or "").capitalize())),
            ("Authentication", "Unique signing link" + (" + access code" if r.get("access_code_set") else "")
             + (f" + email confirmed with a one-time code ({_fmt_ts(r.get('ec_verified_at'))})"
                if r.get("ec_verified_at") else "")
),
            ("Link generated", _fmt_ts(r.get("sent_at"))),
            (("Link emailed", _fmt_ts(r.get("link_emailed_at"))) if r.get("link_emailed_at") else
             ("Marked as shared", _fmt_ts(r.get("notified_at")))),
            ("First viewed", _fmt_ts(r.get("first_viewed_at")) + (f' ({r.get("view_count")} view(s))' if r.get("view_count") else "")),
            ("Consented to e-sign", _fmt_ts(r.get("consented_at"))),
        ]
        if r.get("signed_at"):
            rows.append(("Reviewed" if r.get("role") == "viewer" else "Signed", _fmt_ts(r.get("signed_at"))))
        if r.get("declined_at"):
            rows.append(("Declined", _fmt_ts(r.get("declined_at")) + " — " + _mk(r.get("decline_reason") or "")))
        if r.get("sign_ip"):
            rows.append(("IP address", _mk(r.get("sign_ip")) + ' <font size="7" color="#777777">(as seen by the '
                         'server)</font>'))
        if r.get("sign_ua"):
            rows.append(("Device", _mk((r.get("sign_ua") or "")[:160])))
        if r.get("role") == "signer" and r.get("status") == "signed":
            rows.append(("Signature level", "Simple electronic signature"))
        block = [kv(rows)]
        png = signature_pngs.get(r.get("id"))
        if png:
            try:
                ir = ImageReader(io.BytesIO(png))
                iw, ih = ir.getSize()
                k = min((60 * mm) / iw, (16 * mm) / ih)
                block.append(Table([[Paragraph("Signature", K), RLImage(io.BytesIO(png), width=iw * k, height=ih * k)]],
                                   colWidths=[38 * mm, 135 * mm],
                                   style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "LEFT")])))
            except Exception:
                pass
        block.append(Spacer(1, 3))
        block.append(Table([[""]], colWidths=[173 * mm], style=TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, line)])))
        story.append(KeepTogether(block))

    story.append(Paragraph("Event history (UTC)", H2))
    erows = [[Paragraph("Time", K), Paragraph("Event", K), Paragraph("By", K), Paragraph("IP", K)]]
    for e in env.get("events") or []:
        detail = e.get("detail") or {}
        what = e.get("event", "").replace("_", " ")
        if isinstance(detail, dict) and detail.get("note"):
            what += " — " + str(detail.get("note"))[:120]
        erows.append([Paragraph(_fmt_ts(e.get("ts")), S), Paragraph(_mk(what), S),
                      Paragraph(_mk(e.get("actor") or ""), S), Paragraph(_mk(e.get("ip") or ""), S)])
    et = Table(erows, colWidths=[36 * mm, 70 * mm, 45 * mm, 22 * mm], repeatRows=1)
    et.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, 0), 0.6, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("TOPPADDING", (0, 0), (-1, -1), 1)]))
    story.append(et)

    integ = env.get("integrity") or {}
    last = (env.get("events") or [{}])[-1].get("hash") if env.get("events") else ""
    plan = env.get("seal_plan") or {}
    sealed = status == "completed" and plan.get("configured")
    story.append(Paragraph("Integrity", H2))
    story.append(Paragraph(
        f'The event history above is an append-only, SHA-256 hash-chained log ({len(env.get("events") or [])} '
        f'events{", chain verified intact" if integ.get("ok", True) else ", CHAIN BROKEN"}). Latest event hash: '
        f'<font name="Courier">{last or "—"}</font>. Each document\'s SHA-256 above is of the file exactly as '
        f'uploaded.' + (f' The SHA-256 of this completed PDF is recorded on the envelope and can be checked '
                        f'with {_mk(bn)} → Verify.' if status == "completed" else
                        ' This is not a completed envelope; only a completed envelope\'s final PDF is sealed with a '
                        'recorded hash.'), P))
    if sealed:
        fp = ((plan.get("cert") or {}).get("sha256") or "")
        seal_cn = _seal_cn((plan.get("cert") or {}).get("subject") or "") or f"{bn} Document Seal"
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f'Digital seal: this completed PDF is sealed by {_mk(bn)} with a PAdES digital seal (certificate '
            f'“{_mk(seal_cn)}”, SHA-256 fingerprint <font name="Courier">' + _mk(fp) + '</font>), '
            'and timestamped by an independent RFC 3161 time-stamping authority whenever one answers at sealing. Any '
            'change to the file after sealing '
            f'breaks the seal: check it in your PDF reader\'s Signatures panel or with {_mk(bn)} → Verify. The '
            f'issuing root can be downloaded from this server at /v1/sign/root.crt.', P))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Electronic signature notice: each recipient shown as Signed accessed the documents through a unique link "
        "issued to them, consented to use electronic records and signatures, and adopted their signature to sign. "
        "This record "
        "evidences a simple electronic signature (ESIGN Act / UETA / eIDAS Art. 3(10)). It is not a qualified "
        "electronic signature" + (f"; the digital seal is {_mk(bn)}'s, proving the file is unchanged since completion, "
                                  "not a signer's own signature." if sealed else
                                  " and the PDF is not sealed with a digital certificate."), S))

    eid = env.get("id") or ""

    def _footer(canv, doc):
        canv.saveState()
        canv.setFont("Helvetica", 7)
        canv.setFillColor(mut)
        canv.drawString(18 * mm, 10 * mm, f"{bn} · {heading} · {eid}")
        canv.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canv.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"{heading} — {eid}",
                            author=bn)
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
