"""E-Sign: Word / OpenDocument / RTF uploads (converted to PDF by headless LibreOffice).

Most tests mock the converter process (LibreOffice is often not installed on dev machines): content sniffing, name/content
mismatches, the zip-bomb guard, the no-soffice error, the scrubbed environment + hardened profile, the timeout that
kills the process group, temp-dir cleanup, serialisation, and the end-to-end upload with original/normalized blobs.
The tests marked `real_soffice` run only where soffice exists (set ESIGN_SOFFICE, or put soffice on PATH); the
esignconv privilege-drop test runs only as root in an image that creates that account.
Run: .venv/bin/pytest -q tests/test_esign_docx.py
"""
import hashlib
import io
import re
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import zipfile
from urllib.parse import unquote, urlparse

import pytest

pytest.importorskip("reportlab")
pytest.importorskip("pypdfium2")

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from esign import esign, esign_pdf as P  # noqa: E402
from conftest import build_memory_repo  # noqa: E402

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
A = {"x-owner": "alice"}


# ------------------------------------------------------------------------------------------------- builders
def _pdf(pages=3, size=(595.28, 841.89)) -> bytes:
    from reportlab.pdfgen import canvas
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=size)
    for i in range(pages):
        c.drawString(72, size[1] - 80, f"Converted contract page {i + 1}")
        c.showPage()
    c.save()
    return b.getvalue()


_CT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
       '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
       '<Default Extension="xml" ContentType="application/xml"/>'
       '<Default Extension="png" ContentType="image/png"/>'
       '<Override PartName="/word/document.xml" '
       'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
       '</Types>')
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
         'Target="word/document.xml"/></Relationships>')
_W = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
      'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
      'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
      'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"')


def _para(text: str) -> str:
    from xml.sax.saxutils import escape
    return f'<w:p><w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'


def _docx(paras=("Master Services Agreement", "E-Sign conversion check"), body_xml="", doc_rels=None,
          extra=None, compression=zipfile.ZIP_DEFLATED) -> bytes:
    """A minimal but valid .docx (the three parts Word itself needs), A4 portrait."""
    body = "".join(_para(p) for p in paras) + body_xml
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {_W}><w:body>{body}'
           '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" '
           'w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>')
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression) as z:
        z.writestr("[Content_Types].xml", _CT)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", doc)
        if doc_rels:
            z.writestr("word/_rels/document.xml.rels",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships '
                       'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + doc_rels + '</Relationships>')
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return b.getvalue()


def _odf(mimetype=b"application/vnd.oasis.opendocument.text", text="E-Sign ODT check.") -> bytes:
    """A minimal valid OpenDocument file: stored `mimetype` first, then manifest + content."""
    from xml.sax.saxutils import escape
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), mimetype)            # stored, first — as ODF requires
        z.writestr("META-INF/manifest.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><manifest:manifest '
                   'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">'
                   f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mimetype.decode()}"/>'
                   '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
                   '</manifest:manifest>', zipfile.ZIP_DEFLATED)
        z.writestr("content.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><office:document-content '
                   'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
                   'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2">'
                   f'<office:body><office:text><text:p>{escape(text)}</text:p></office:text></office:body>'
                   '</office:document-content>', zipfile.ZIP_DEFLATED)
    return b.getvalue()


def _ooxml(main_part: str, ct_word: str) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", f'<Types><Override PartName="/{main_part}" ContentType="application/'
                                          f'vnd.openxmlformats-officedocument.{ct_word}.main+xml"/></Types>')
        z.writestr(main_part, "<x/>")
    return b.getvalue()


def _ole(*streams: str) -> bytes:
    """Enough of an OLE2 compound file for the sniffer: the magic + directory entry names (UTF-16LE)."""
    body = b"".join(s.encode("utf-16-le").ljust(64, b"\0") for s in streams)
    return P._OLE_MAGIC + b"\0" * 504 + body + b"\0" * 1024


RTF = b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times New Roman;}}\\f0\\fs24 E-Sign RTF check.\\par}"


def _detect(data, name):
    return P.detect_office_format(data, name)


def _err(fn, *a, **kw) -> str:
    with pytest.raises(P.PdfError) as ei:
        fn(*a, **kw)
    return str(ei.value)


# ------------------------------------------------------------------------------------------------- fake LibreOffice
class FakeProc:
    def __init__(self, cmd, kw, rc=0, hang=False, on_run=None):
        self.cmd, self.kw, self.pid, self.returncode = cmd, kw, 424242, None
        self._rc, self._hang, self.waits, self.killed = rc, hang, [], False
        if on_run:
            on_run(self)

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self._hang and len(self.waits) == 1:
            raise subprocess.TimeoutExpired(self.cmd, timeout)
        self.returncode = -9 if self.killed else self._rc
        return self.returncode

    def kill(self):
        self.killed = True

    # helpers to read the arguments the converter was given
    def arg_after(self, flag):
        return self.cmd[self.cmd.index(flag) + 1]

    @property
    def profile(self):
        uri = [a for a in self.cmd if a.startswith("-env:UserInstallation=")][0].split("=", 1)[1]
        return unquote(urlparse(uri).path)

    @property
    def inpath(self):
        return self.cmd[-1]


@pytest.fixture
def fake_lo(monkeypatch, tmp_path):
    """Pretend soffice exists; each run writes `state['pdf']` as the output unless told otherwise."""
    conv_root = tmp_path / "conv"
    conv_root.mkdir()
    monkeypatch.setenv("ESIGN_CONVERT_TMP", str(conv_root))
    monkeypatch.setattr(P, "find_soffice", lambda: "/fake/soffice")
    monkeypatch.setattr(P, "_prlimit_path", lambda: None)
    monkeypatch.setattr(P, "_convert_identity", lambda: None)
    state = {"pdf": _pdf(2), "rc": 0, "hang": False, "procs": [], "write": True, "seen": {}}

    def on_run(proc):
        outdir = proc.arg_after("--outdir")
        state["seen"] = {
            "xcu": open(os.path.join(proc.profile, "user", "registrymodifications.xcu"), encoding="utf-8").read(),
            "input": open(proc.inpath, "rb").read(),
            "input_mode": stat.S_IMODE(os.stat(proc.inpath).st_mode),
            "outdir": outdir,
        }
        if state["write"] and not state["hang"]:
            with open(os.path.join(outdir, "input.pdf"), "wb") as f:
                f.write(state["pdf"])

    def spawn(cmd, **kw):
        p = FakeProc(cmd, kw, rc=state["rc"], hang=state["hang"], on_run=on_run)
        state["procs"].append(p)
        return p

    monkeypatch.setattr(P, "_spawn", spawn)
    state["root"] = conv_root
    return state


# ------------------------------------------------------------------------------------------------- detection
def test_detects_word_formats_by_content_not_name():
    d = _docx()
    assert _detect(d, "contract.docx") == "docx"
    assert _detect(d, "CONTRACT.DOCX") == "docx"
    assert _detect(d, "contract") == "docx"                       # no extension: judged by content
    assert _detect(d, "contract.doc") == "docx"                   # Word happily opens a .docx saved as .doc
    assert _detect(_odf(), "terms.odt") == "odt"
    assert _detect(_ole("Root Entry", "WordDocument", "1Table"), "old.doc") == "doc"
    assert _detect(RTF, "letter.rtf") == "rtf"
    assert _detect(b"\xef\xbb\xbf\r\n  " + RTF, "letter.doc") == "rtf"   # .doc holding RTF is common
    # PDFs / images / random files are not office documents
    assert _detect(_pdf(1), "x.pdf") is None
    assert _detect(b"hello world", "notes.txt") is None


def test_name_and_content_mismatches_are_rejected():
    d = _docx()
    m = _err(_detect, d, "contract.pdf")
    assert "Word document" in m and "not a PDF" in m and ".docx" in m
    assert "doesn't match" in _err(_detect, _odf(), "terms.docx")
    assert "doesn't match" in _err(_detect, d, "terms.odt")
    assert "doesn't match" in _err(_detect, d, "archive.zip")
    m = _err(_detect, b"PK\x03\x04 not a zip", "contract.docx")
    assert "isn't a valid Word document" in m and "PDF" in m
    assert "isn't a valid OpenDocument" in _err(_detect, b"garbage", "terms.odt")
    assert "web page" in _err(_detect, b"<html><body>Contract</body></html>", "contract.doc")
    # the whole upload path: nothing recognisable at all
    m = _err(P.normalize_upload, b"just some text", "notes.txt")
    assert "Word document" in m and "PDF" in m and "PNG" in m


def test_recognised_but_unsupported_office_files():
    assert "Spreadsheets" in _err(_detect, _ooxml("xl/workbook.xml", "spreadsheetml.sheet"), "a.xlsx")
    assert "Presentations" in _err(_detect, _ooxml("ppt/presentation.xml", "presentationml.presentation"), "a.pptx")
    assert "Spreadsheets" in _err(_detect, _odf(b"application/vnd.oasis.opendocument.spreadsheet"), "a.ods")
    assert "Password-protected" in _err(_detect, _ole("EncryptionInfo", "EncryptedPackage"), "locked.docx")
    assert "Spreadsheets" in _err(_detect, _ole("Workbook"), "old.xls")
    assert "Outlook" in _err(_detect, _ole("__substg1.0_0037001F"), "mail.msg")
    # a zip entry flagged as encrypted
    z = bytearray(_docx())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = z.find(sig)
        while i >= 0:
            z[i + off] |= 0x1
            i = z.find(sig, i + 4)
    assert "Password-protected" in _err(_detect, bytes(z), "locked.docx")


# ------------------------------------------------------------------------------------------------- zip bomb guard
def test_zip_bomb_guard_never_reaches_the_converter(monkeypatch):
    calls = []
    monkeypatch.setattr(P, "office_to_pdf", lambda data, fmt: calls.append(fmt) or _pdf(1))
    # 1) a highly compressible entry: 20 MB of zeros deflates ~1000:1
    bomb = _docx(extra={"word/media/filler.bin": b"\0" * (20 * 1024 * 1024)})
    assert len(bomb) < 200 * 1024
    assert "far more data" in _err(P.normalize_upload, bomb, "bomb.docx")
    # 2) total declared size over the budget
    monkeypatch.setattr(P, "MAX_OFFICE_UNZIPPED", 200_000)
    big = _docx(extra={"word/media/photo.bin": os.urandom(300_000)})
    assert "far more data" in _err(P.normalize_upload, big, "big.docx")
    monkeypatch.setattr(P, "MAX_OFFICE_UNZIPPED", 160 * 1024 * 1024)
    # 3) too many entries
    monkeypatch.setattr(P, "MAX_OFFICE_ZIP_ENTRIES", 20)
    many = _docx(extra={f"word/media/i{i}.png": b"x" for i in range(30)})
    assert "too many internal parts" in _err(P.normalize_upload, many, "many.docx")
    monkeypatch.setattr(P, "MAX_OFFICE_ZIP_ENTRIES", 3000)
    # 4) a corrupted entry (CRC mismatch) is reported as damaged
    ok = _docx(compression=zipfile.ZIP_STORED)
    i = ok.index(b"E-Sign conversion check")
    bad = ok[:i] + b"B" + ok[i + 1:]
    assert "damaged" in _err(P.normalize_upload, bad, "bad.docx")
    assert calls == []
    # and a sane document passes the guard and is handed to the converter
    out = P.normalize_upload(_docx(), "fine.docx")
    assert calls == ["docx"] and out["kind"] == "document" and out["source_format"] == "docx"


# ------------------------------------------------------------------------------------------------- converter process
def test_no_soffice_is_a_user_safe_error(monkeypatch):
    monkeypatch.setattr(P, "find_soffice", lambda: None)
    m = _err(P.office_to_pdf, _docx(), "docx")
    assert "can't be converted on this server" in m and "PDF" in m


def test_find_soffice_honours_override(monkeypatch, tmp_path):
    exe = tmp_path / "soffice"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    monkeypatch.setenv("ESIGN_SOFFICE", str(exe))
    assert P.find_soffice() == str(exe)


def test_conversion_runs_hardened_and_cleans_up(fake_lo, monkeypatch):
    monkeypatch.setenv("ESIGN_SMTP_PASS", "sk-test-should-not-leak")
    monkeypatch.setenv("ESIGN_DATABASE_URL", "postgresql://secret@db/esign")
    data = _docx()
    pdf = P.office_to_pdf(data, "docx")
    assert pdf == fake_lo["pdf"]
    proc = fake_lo["procs"][0]
    cmd, kw = proc.cmd, proc.kw
    assert cmd[0] == "/fake/soffice"
    for flag in ("--headless", "--norestore", "--nolockcheck", "--nodefault", "--nologo"):
        assert flag in cmd
    assert proc.arg_after("--convert-to") == "pdf:writer_pdf_Export"
    assert proc.inpath.endswith(os.sep + "input.docx")
    # fresh profile under the private work dir, pre-seeded with the lock-down settings
    xcu = fake_lo["seen"]["xcu"]
    assert '"DisableMacrosExecution"' in xcu and "<value>true</value>" in xcu
    assert '<prop oor:name="BlockUntrustedRefererLinks" oor:op="fuse"><value>true</value>' in xcu
    assert '<prop oor:name="Link" oor:op="fuse"><value>0</value>' in xcu          # 0 = NEVER update links
    assert '<prop oor:name="DisableActiveContent" oor:op="fuse"><value>true</value>' in xcu
    assert '<prop oor:name="ooInetProxyType" oor:op="fuse"><value>2</value>' in xcu
    assert fake_lo["seen"]["input"] == data and fake_lo["seen"]["input_mode"] == 0o600
    # process: own session (so the timeout can kill soffice.bin too), no stdin, scrubbed environment
    assert kw["start_new_session"] is True and kw["stdin"] == subprocess.DEVNULL and kw["umask"] == 0o077
    env = kw["env"]
    assert "ESIGN_SMTP_PASS" not in env and "ESIGN_DATABASE_URL" not in env
    assert not any("sk-test" in v or "secret@" in v for v in env.values())
    work = os.path.dirname(fake_lo["seen"]["outdir"])
    assert env["HOME"] == work and env["TMPDIR"].startswith(work)
    assert env["https_proxy"] == env["HTTP_PROXY"] == "http://127.0.0.1:9" and env["no_proxy"] == ""
    assert "user" not in kw                                     # not root here: no privilege drop
    assert proc.waits == [P.OFFICE_TIMEOUT_S]
    # everything under the temp root is gone, and the slot is free again
    assert list(fake_lo["root"].iterdir()) == []
    assert P._CONVERT_SLOT.acquire(blocking=False)
    P._CONVERT_SLOT.release()


def test_prlimit_and_privilege_drop_when_root(fake_lo, monkeypatch):
    chowned = []
    monkeypatch.setattr(P, "_prlimit_path", lambda: "/usr/bin/prlimit")
    monkeypatch.setattr(P, "_convert_identity", lambda: (4321, 4322))
    monkeypatch.setattr(P.os, "chown", lambda path, uid, gid: chowned.append((path, uid, gid)))
    P.office_to_pdf(_docx(), "docx")
    proc = fake_lo["procs"][0]
    assert proc.cmd[0] == "/usr/bin/prlimit" and proc.cmd[proc.cmd.index("--") + 1] == "/fake/soffice"
    assert any(a.startswith("--cpu=") for a in proc.cmd) and any(a.startswith("--fsize=") for a in proc.cmd)
    assert proc.kw["user"] == 4321 and proc.kw["group"] == 4322 and proc.kw["extra_groups"] == []
    paths = {os.path.basename(p) for p, u, g in chowned if (u, g) == (4321, 4322)}
    assert {"input.docx", "registrymodifications.xcu", "out", "profile", "tmp"} <= paths
    assert list(fake_lo["root"].iterdir()) == []


def test_convert_identity_rules(monkeypatch):
    import pwd

    class PW:
        pw_uid, pw_gid = 999, 998
    monkeypatch.setattr(P.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pwd, "getpwnam", lambda n: PW if n == "esignconv" else (_ for _ in ()).throw(KeyError(n)))
    monkeypatch.delenv("ESIGN_CONVERT_USER", raising=False)
    assert P._convert_identity() == (999, 998)
    monkeypatch.setenv("ESIGN_CONVERT_USER", "")
    assert P._convert_identity() is None                            # explicitly disabled
    monkeypatch.setenv("ESIGN_CONVERT_USER", "nobody-here")
    assert P._convert_identity() is None                            # account missing: run as is (logged once)
    monkeypatch.delenv("ESIGN_CONVERT_USER", raising=False)
    monkeypatch.setattr(P.os, "geteuid", lambda: 1000)
    assert P._convert_identity() is None                            # not root: nothing to drop


def test_timeout_kills_the_process_group_and_cleans_up(fake_lo, monkeypatch):
    killed = []
    monkeypatch.setattr(P.os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))
    fake_lo["hang"] = True
    m = _err(P.office_to_pdf, _docx(), "docx")
    assert "took too long" in m and str(P.OFFICE_TIMEOUT_S) in m
    proc = fake_lo["procs"][0]
    assert (424242, signal.SIGKILL) in killed and proc.killed
    assert proc.waits[0] == P.OFFICE_TIMEOUT_S and len(proc.waits) == 2      # killed, then reaped
    assert list(fake_lo["root"].iterdir()) == []
    assert P._CONVERT_SLOT.acquire(blocking=False)
    P._CONVERT_SLOT.release()


def test_failed_runs_and_bad_output_are_user_safe(fake_lo, monkeypatch, tmp_path):
    monkeypatch.setattr(P.os, "killpg", lambda pgid, sig: None)
    fake_lo["rc"] = 1                                               # LibreOffice error
    assert "couldn't be converted" in _err(P.office_to_pdf, _docx(), "docx")
    fake_lo["rc"], fake_lo["write"] = 0, False                       # "success" but no output (load failure)
    assert "couldn't be converted" in _err(P.office_to_pdf, _docx(), "docx")
    fake_lo["write"], fake_lo["pdf"] = True, b"not a pdf at all"      # output that isn't a PDF
    assert "couldn't be converted" in _err(P.office_to_pdf, _docx(), "docx")
    fake_lo["pdf"] = _pdf(1)                                         # output larger than the limit
    monkeypatch.setattr(P, "MAX_FILE_BYTES", len(fake_lo["pdf"]) - 1)
    small = _docx(compression=zipfile.ZIP_DEFLATED)
    assert len(small) <= P.MAX_FILE_BYTES
    assert "larger than 25 MB" in _err(P.office_to_pdf, small, "docx")
    monkeypatch.setattr(P, "MAX_FILE_BYTES", 25 * 1024 * 1024)
    # output that is a symlink (to a real PDF) is refused, not followed
    target = tmp_path / "elsewhere.pdf"
    target.write_bytes(_pdf(1))
    fake_lo["write"] = False

    def spawn(cmd, **kw):
        p = FakeProc(cmd, kw)
        os.symlink(target, os.path.join(p.arg_after("--outdir"), "input.pdf"))
        return p
    monkeypatch.setattr(P, "_spawn", spawn)
    assert "couldn't be converted" in _err(P.office_to_pdf, _docx(), "docx")

    def boom(cmd, **kw):
        raise PermissionError("setuid not permitted")
    monkeypatch.setattr(P, "_spawn", boom)
    assert "couldn't be converted" in _err(P.office_to_pdf, _docx(), "docx")
    assert list(fake_lo["root"].iterdir()) == []
    assert P._CONVERT_SLOT.acquire(blocking=False)
    P._CONVERT_SLOT.release()


def test_unexpected_errors_are_user_safe_not_500(fake_lo, monkeypatch):
    def full(*a, **kw):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(P.tempfile, "mkdtemp", full)
    assert "couldn't be converted" in _err(P.office_to_pdf, _docx(), "docx")
    assert P._CONVERT_SLOT.acquire(blocking=False)
    P._CONVERT_SLOT.release()


def test_conversions_are_serialised_and_busy_is_reported(fake_lo, monkeypatch):
    active, peak, lock = [0], [0], threading.Lock()

    def spawn(cmd, **kw):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        p = FakeProc(cmd, kw)
        with open(os.path.join(p.arg_after("--outdir"), "input.pdf"), "wb") as f:
            f.write(fake_lo["pdf"])
        with lock:
            active[0] -= 1
        return p
    monkeypatch.setattr(P, "_spawn", spawn)
    results, errors = [], []

    def run():
        try:
            results.append(P.office_to_pdf(_docx(), "docx"))
        except Exception as e:                                      # pragma: no cover - reported below
            errors.append(e)
    ts = [threading.Thread(target=run) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert not errors and len(results) == 4 and peak[0] == 1
    # the slot held elsewhere for longer than the queue wait -> a friendly "busy"
    monkeypatch.setattr(P, "OFFICE_QUEUE_WAIT_S", 0.05)
    assert P._CONVERT_SLOT.acquire(blocking=False)
    try:
        assert "being converted right now" in _err(P.office_to_pdf, _docx(), "docx")
    finally:
        P._CONVERT_SLOT.release()
    assert list(fake_lo["root"].iterdir()) == []


def _stand_in_soffice(tmp_path, mode, pdf_path=None):
    """A real executable that behaves like `soffice --convert-to pdf` (or hangs with a child, like oosplash +
    soffice.bin), so the real subprocess / session / kill / cleanup code runs without LibreOffice."""
    import sys
    report = tmp_path / "report.json"
    exe = tmp_path / "soffice"
    exe.write_text(f"""#!{sys.executable}
import json, os, subprocess, sys, time
args = sys.argv[1:]
outdir, inp = args[args.index("--outdir") + 1], args[-1]
info = dict(args=args, env=dict(os.environ), cwd=os.getcwd(), pid=os.getpid(), sid=os.getsid(0),
            input_size=os.path.getsize(inp), stdin_tty=os.isatty(0))
if {mode!r} == "hang":
    info["child"] = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]).pid
    json.dump(info, open({str(report)!r}, "w"))
    time.sleep(60)
json.dump(info, open({str(report)!r}, "w"))
print("convert", inp, "->", outdir, "using filter : writer_pdf_Export")
if {mode!r} == "fail":
    print("Error: source file could not be loaded")
    sys.exit(1)
with open(os.path.join(outdir, "input.pdf"), "wb") as f, open({str(pdf_path)!r}, "rb") as src:
    f.write(src.read())
""")
    exe.chmod(0o755)
    return exe, report


def _stand_in_env(monkeypatch, tmp_path, exe):
    conv_root = tmp_path / "conv"
    conv_root.mkdir(exist_ok=True)
    monkeypatch.setenv("ESIGN_CONVERT_TMP", str(conv_root))
    monkeypatch.setenv("ESIGN_SOFFICE", str(exe))
    monkeypatch.setenv("ESIGN_SMTP_PASS", "sk-test-should-not-leak")
    monkeypatch.setattr(P, "find_soffice", P.find_soffice)          # the real lookup, honouring ESIGN_SOFFICE
    monkeypatch.setattr(P, "_prlimit_path", lambda: None)
    monkeypatch.setattr(P, "_convert_identity", lambda: None)
    return conv_root


def test_real_subprocess_with_a_stand_in_converter(monkeypatch, tmp_path):
    import json
    pdf_path = tmp_path / "out.pdf"
    pdf_path.write_bytes(_pdf(2))
    exe, report = _stand_in_soffice(tmp_path, "ok", pdf_path)
    conv_root = _stand_in_env(monkeypatch, tmp_path, exe)
    data = _docx()
    assert P.office_to_pdf(data, "docx") == pdf_path.read_bytes()
    info = json.loads(report.read_text())
    assert info["sid"] == info["pid"]                               # its own session (killable as a group)
    assert info["input_size"] == len(data) and not info["stdin_tty"]
    assert "ESIGN_SMTP_PASS" not in info["env"] and info["env"]["HOME"].startswith(str(conv_root))
    assert info["cwd"].startswith(str(conv_root))
    assert list(conv_root.iterdir()) == []
    # a failing run is a user-safe error, also cleaned up
    exe, report = _stand_in_soffice(tmp_path, "fail")
    assert "couldn't be converted" in _err(P.office_to_pdf, data, "docx")
    assert list(conv_root.iterdir()) == []


def _running(pid: int) -> bool:
    """True while `pid` is a live process. A killed orphan may linger as a zombie when its new parent (PID 1 in a
    container without an init) never reaps it — that is dead too."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        pass
    try:
        st = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout
        return bool(st.strip()) and not st.strip().startswith("Z")
    except Exception:
        return True


def test_real_timeout_kills_launcher_and_its_child(monkeypatch, tmp_path):
    import json
    exe, report = _stand_in_soffice(tmp_path, "hang")
    conv_root = _stand_in_env(monkeypatch, tmp_path, exe)
    monkeypatch.setattr(P, "OFFICE_TIMEOUT_S", 2)
    t0 = time.time()
    assert "took too long" in _err(P.office_to_pdf, _docx(), "docx")
    assert time.time() - t0 < 15
    child = json.loads(report.read_text())["child"]
    deadline = time.time() + 5
    while time.time() < deadline:                                   # the orphaned "soffice.bin" must be gone too
        if not _running(child):
            break
        time.sleep(0.05)
    else:
        os.kill(child, signal.SIGKILL)
        pytest.fail("the converter's child process survived the timeout")
    assert list(conv_root.iterdir()) == []


def test_converted_page_limit_message_names_the_document(monkeypatch):
    monkeypatch.setattr(P, "office_to_pdf", lambda data, fmt: _pdf(3))
    m = _err(P.normalize_upload, _docx(), "long.docx", max_pages=2)
    assert m == "The converted document has 3 pages — the limit is 2."


def test_dockerfile_ships_the_converter_and_its_sandbox():
    """The image must provide what office_to_pdf expects: soffice from a minimal LibreOffice install, contract fonts,
    and LibreOffice never running as root (either the esignconv drop or a non-root USER for the whole app)."""
    from pathlib import Path
    df = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    for needle in ("libreoffice-writer-nogui", "--no-install-recommends", "fonts-liberation",
                   "fonts-crosextra-carlito", "fonts-noto-core", "useradd --system", " esignconv", "chmod 0750 /app",
                   "chmod 0700 /data"):
        assert needle in df, needle
    assert "--proxy-headers" not in df and "forwarded-allow-ips" not in df


# ------------------------------------------------------------------------------------------------- API end to end
@pytest.fixture
def ctx(monkeypatch):
    monkeypatch.delenv("ESIGN_ENC_KEY", raising=False)
    repo = build_memory_repo()

    def rk(request, key):
        o = request.headers.get("x-owner")
        if not o:
            raise HTTPException(status_code=401, detail="authentication required")
        return o

    esign.configure(lambda: repo, require_key=rk, session_label=lambda r: None)
    esign._RL.clear()
    app = FastAPI()
    app.include_router(esign.router)
    return TestClient(app), repo


def _new_env(c, title="MSA"):
    r = c.post("/v1/esign/envelopes", json={"title": title, "message": "Please sign"}, headers=A)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _upload(c, eid, data, name, ctype=DOCX_MIME):
    return c.post(f"/v1/esign/envelopes/{eid}/documents", files={"file": (name, data, ctype)}, headers=A)


def _blobs(repo, owner="alice"):
    return [r for r in repo.list_documents(owner, pipeline="esign_blob", limit=1000)]


def test_docx_upload_keeps_original_and_signs_the_converted_pdf(ctx, monkeypatch):
    c, repo = ctx
    conv = _pdf(3)
    seen = []
    monkeypatch.setattr(P, "office_to_pdf", lambda data, fmt: seen.append((len(data), fmt)) or conv)
    data = _docx()
    eid = _new_env(c)
    r = _upload(c, eid, data, "Master Services Agreement.docx")
    assert r.status_code == 200, r.text
    d = r.json()
    assert seen == [(len(data), "docx")]
    assert d["kind"] == "document" and d["source_format"] == "docx" and d["content_type_original"] == DOCX_MIME
    assert d["page_count"] == 3 and len(d["pages"]) == 3 and abs(d["pages"][0]["w"] - 595.28) < 0.5
    assert d["sha256_original"] == hashlib.sha256(data).hexdigest() and d["size"] == len(data)
    assert "blob_id" not in d and "original_blob_id" not in d
    # blobs: the original is the .docx exactly as uploaded (with its real type); the normalized one is the PDF
    env = esign._load(eid, "alice")
    doc = env["documents"][0]
    orig = repo.get_document(doc["original_blob_id"], "alice")
    norm = repo.get_document(doc["blob_id"], "alice")
    assert orig["data"] == data and orig["content_type"] == DOCX_MIME
    assert norm["content_type"] == "application/pdf" and P.page_count(norm["data"]) == 3
    assert doc["sha256_converted"] == hashlib.sha256(norm["data"]).hexdigest()
    assert any("converted to PDF from DOCX" in str((e.get("detail") or {}).get("note")) for e in env["events"])
    # the hash of the PDF the signers will see is in the hash-chained event, not only on the document record
    added = [e for e in env["events"] if e.get("event") == "document_added"][-1]
    assert (added.get("detail") or {}).get("sha256_converted") == doc["sha256_converted"]
    # pages render from the converted PDF
    png = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/pages/2.png?scale=1", headers=A)
    assert png.status_code == 200 and png.content[:4] == b"\x89PNG"
    # owner downloads: original = the .docx, current = the PDF
    o = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/file?which=original", headers=A)
    assert o.status_code == 200 and o.content == data
    assert o.headers["content-type"].startswith(DOCX_MIME)
    assert 'filename="Master Services Agreement.docx"' in o.headers["content-disposition"]
    cur = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/file?which=current", headers=A)
    assert cur.status_code == 200 and cur.content[:5] == b"%PDF-" and cur.headers["content-type"] == "application/pdf"
    assert cur.headers["content-disposition"].endswith('.pdf"')
    # the converted document goes through the normal signing flow to a completed, flattened PDF
    s = c.put(f"/v1/esign/envelopes/{eid}/recipients", headers=A,
              json={"recipients": [{"name": "Sam Signer", "email": "sam@example.com", "role": "signer"}]}).json()["recipients"][0]
    f = c.put(f"/v1/esign/envelopes/{eid}/fields", headers=A, json={"fields": [
        dict(recipient_id=s["id"], document_id=d["id"], page=3, x=.5, y=.8, w=.25, h=.05, type="signature")]})
    assert f.status_code == 200, f.text
    assert c.post(f"/v1/esign/envelopes/{eid}/send", headers=A).status_code == 200
    link = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["recipients"][0]["link"]
    tok = link.split("/sign/")[1]
    assert c.post(f"/v1/sign/{tok}/consent").status_code == 200
    fid = c.get(f"/v1/sign/{tok}/session").json()["fields"][0]["id"]
    import base64
    from PIL import Image, ImageDraw
    im = Image.new("RGBA", (300, 90), (0, 0, 0, 0))
    ImageDraw.Draw(im).line([(10, 70), (150, 15), (290, 60)], fill=(20, 20, 70, 255), width=6)
    b = io.BytesIO()
    im.save(b, "PNG")
    sig = "data:image/png;base64," + base64.b64encode(b.getvalue()).decode()
    done = c.post(f"/v1/sign/{tok}/complete", json={"values": {fid: "adopted"}, "signature": sig, "adopted_name": "Sam Signer"})
    assert done.status_code == 200, done.text
    fin = c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()
    assert fin["status"] == "completed"
    dl = c.get(f"/v1/esign/envelopes/{eid}/download?kind=combined", headers=A)
    assert dl.status_code == 200 and dl.content[:5] == b"%PDF-" and P.page_count(dl.content) >= 4   # 3 + certificate
    cert = c.get(f"/v1/esign/envelopes/{eid}/download?kind=certificate", headers=A)
    cert_text = " ".join(_pdf_text(cert.content).split())
    assert "converted to PDF from DOCX" in cert_text and hashlib.sha256(data).hexdigest()[:16] in cert_text.replace(" ", "")
    # the original .docx is still downloadable after completion
    o2 = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/file?which=original", headers=A)
    assert o2.content == data


def test_original_keeps_users_word_extension_and_duplicates(ctx, monkeypatch):
    c, repo = ctx
    monkeypatch.setattr(P, "office_to_pdf", lambda data, fmt: _pdf(1))
    eid = _new_env(c)
    d = _upload(c, eid, RTF, "Side letter.doc", "application/msword").json()
    assert d["source_format"] == "rtf" and d["content_type_original"] == "application/rtf"
    o = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/file?which=original", headers=A)
    assert o.content == RTF and 'filename="Side letter.doc"' in o.headers["content-disposition"]
    od = _upload(c, eid, _odf(), "Terms.odt", "application/vnd.oasis.opendocument.text").json()
    assert od["source_format"] == "odt"
    o = c.get(f"/v1/esign/envelopes/{eid}/documents/{od['id']}/file?which=original", headers=A)
    assert o.headers["content-type"].startswith("application/vnd.oasis.opendocument.text")
    assert 'filename="Terms.odt"' in o.headers["content-disposition"]
    # duplicate keeps the original Word file and its type
    dup = c.post(f"/v1/esign/envelopes/{eid}/duplicate", headers=A).json()
    nd = [x for x in dup["documents"] if x["name"] == "Side letter.doc"][0]
    assert nd["source_format"] == "rtf"
    o = c.get(f"/v1/esign/envelopes/{dup['id']}/documents/{nd['id']}/file?which=original", headers=A)
    assert o.content == RTF and o.headers["content-type"].startswith("application/rtf")
    # PDFs and images are unchanged
    pdf = _pdf(1)
    p = _upload(c, eid, pdf, "plain.pdf", "application/pdf").json()
    assert p["kind"] == "pdf" and p["content_type_original"] == "application/pdf" and "source_format" not in p


def test_api_rejections_store_nothing(ctx, monkeypatch):
    c, repo = ctx
    eid = _new_env(c)
    calls = []
    monkeypatch.setattr(P, "find_soffice", lambda: None)
    r = _upload(c, eid, _docx(), "contract.docx")
    assert r.status_code == 422 and "can't be converted on this server" in r.json()["detail"]
    monkeypatch.setattr(P, "office_to_pdf", lambda data, fmt: calls.append(fmt) or _pdf(1))
    r = _upload(c, eid, _docx(), "contract.pdf", "application/pdf")
    assert r.status_code == 422 and "not a PDF" in r.json()["detail"]
    r = _upload(c, eid, _ooxml("xl/workbook.xml", "spreadsheetml.sheet"), "numbers.xlsx")
    assert r.status_code == 422 and "Spreadsheets" in r.json()["detail"]
    assert calls == [] and _blobs(repo) == []
    assert c.get(f"/v1/esign/envelopes/{eid}", headers=A).json()["documents"] == []


# ------------------------------------------------------------------------------------------------- real LibreOffice
real_soffice = pytest.mark.skipif(P.find_soffice() is None, reason="LibreOffice (soffice) not installed — runs in the Docker image")


def _pdf_text(pdf: bytes) -> str:
    from pypdf import PdfReader
    return "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(pdf)).pages)


@real_soffice
def test_real_docx_conversion():
    data = _docx(paras=("Master Services Agreement", "E-Sign conversion check",
                        "Договор об оказании услуг", "عقد خدمات", "服务合同"))
    out = P.normalize_upload(data, "msa.docx")
    assert out["kind"] == "document" and out["source_format"] == "docx" and len(out["pages"]) == 1
    assert abs(out["pages"][0]["w"] - 595.3) < 2 and abs(out["pages"][0]["h"] - 841.9) < 2     # A4 from sectPr
    text = _pdf_text(out["pdf"])
    assert "E-Sign conversion check" in text
    assert "Договор" in text                                     # Cyrillic glyphs present (fonts installed)


@real_soffice
def test_real_rtf_and_odt_conversion():
    out = P.normalize_upload(RTF, "letter.rtf")
    assert out["source_format"] == "rtf" and len(out["pages"]) >= 1
    assert "E-Sign RTF check" in _pdf_text(out["pdf"])
    out = P.normalize_upload(_odf(), "terms.odt")
    assert out["source_format"] == "odt" and len(out["pages"]) >= 1
    assert "E-Sign ODT check" in _pdf_text(out["pdf"])


def _linking_docx(img: str, secret: str) -> bytes:
    """A .docx that shows a linked (not embedded) local image and INCLUDETEXTs a local file."""
    drawing = ('<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
               '<wp:extent cx="952500" cy="590550"/><wp:docPr id="1" name="Linked"/>'
               '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
               '<pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="linked.png"/><pic:cNvPicPr/></pic:nvPicPr>'
               '<pic:blipFill><a:blip r:link="rIdImg"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
               '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="952500" cy="590550"/></a:xfrm>'
               '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic>'
               '</wp:inline></w:drawing></w:r></w:p>')
    include = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> '
               f'INCLUDETEXT "{secret}" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r>'
               '<w:r><w:t>placeholder</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    rels = ('<Relationship Id="rIdImg" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            f'image" Target="file://{img}" TargetMode="External"/>')
    return _docx(body_xml=drawing + include, doc_rels=rels)


def _leaks(public: bool):
    """Convert a linking document whose targets are private (0700 dir) or world-readable; return what leaked."""
    from PIL import Image
    from pypdf import PdfReader
    d = tempfile.mkdtemp(prefix="esign-linktest-")
    try:
        if public:
            os.chmod(d, 0o755)
        img, secret = os.path.join(d, "linked.png"), os.path.join(d, "secret.txt")
        Image.new("RGB", (37, 23), (200, 30, 30)).save(img)
        with open(secret, "w") as f:
            f.write("ESIGN-LINK-LEAK-MARKER-7f3c")
        for p in (img, secret):
            os.chmod(p, 0o644 if public else 0o600)
        out = P.normalize_upload(_linking_docx(img, secret), "linked.docx")
        leaked = []
        if "ESIGN-LINK-LEAK-MARKER" in _pdf_text(out["pdf"]):
            leaked.append("INCLUDETEXT text")

        def images(res, seen):
            xo = (res or {}).get("/XObject") or {}
            for k in xo:
                o = xo[k].get_object()
                if o.get("/Subtype") == "/Image":
                    seen.append((int(o.get("/Width", 0)), int(o.get("/Height", 0))))
                elif o.get("/Subtype") == "/Form":
                    images(o.get("/Resources"), seen)
            return seen
        found = []
        for pg in PdfReader(io.BytesIO(out["pdf"])).pages:
            images(pg.get("/Resources"), found)
        if (37, 23) in found:
            leaked.append("linked image")
        return leaked
    finally:
        shutil.rmtree(d, ignore_errors=True)


@real_soffice
@pytest.mark.skipif(P._convert_identity() is None, reason="needs the root + esignconv set-up of the Docker image")
def test_real_conversion_cannot_read_files_private_to_the_api():
    """The production property: a hostile document cannot pull files the API can read (keys, data) into the PDF —
    LibreOffice runs as esignconv, which cannot read them."""
    assert _leaks(public=False) == []


@real_soffice
def test_real_conversion_link_blocking_for_world_readable_files():
    """Defence in depth: the hardened profile (BlockUntrustedRefererLinks, link updates never) should stop
    LibreOffice following links even to world-readable files. Reported as a warning rather than a failure: the
    account drop and the closed /srv directory are what protect the API's files."""
    import warnings
    leaked = _leaks(public=True)
    if leaked:
        warnings.warn(f"LibreOffice followed links to world-readable local files ({', '.join(leaked)}); only the "
                      f"esignconv account + the 0750 /srv directory stop it reaching the API's files", UserWarning)


@real_soffice
def test_real_docx_upload_through_the_api(ctx):
    c, repo = ctx
    eid = _new_env(c)
    data = _docx()
    r = _upload(c, eid, data, "Real.docx")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["source_format"] == "docx" and d["page_count"] == 1
    png = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/pages/1.png?scale=1", headers=A)
    assert png.status_code == 200 and png.content[:4] == b"\x89PNG"
    o = c.get(f"/v1/esign/envelopes/{eid}/documents/{d['id']}/file?which=original", headers=A)
    assert o.content == data and 'filename="Real.docx"' in o.headers["content-disposition"]



def test_a_queue_beyond_the_waiting_cap_is_busy_at_once(monkeypatch):
    """A burst of Word uploads must not park the API's shared worker threads: one converts, OFFICE_MAX_WAITING
    wait, anyone beyond that gets 'busy' immediately instead of holding a thread for 30 s."""
    monkeypatch.setattr(P, "find_soffice", lambda: "/bin/true")
    monkeypatch.setattr(P, "_WAITING", [P.OFFICE_MAX_WAITING])
    t = time.monotonic()
    assert "being converted right now" in _err(P.office_to_pdf, _docx(), "docx")
    assert time.monotonic() - t < 1.0


def test_certificate_shows_the_hash_of_the_pdf_signers_saw():
    from esign import esign_pdf
    env = {"title": "MSA", "status": "completed", "id": "e" * 32, "owner": "o", "recipients": [], "events": [],
           "documents": [{"name": "MSA.docx", "page_count": 2, "order": 0, "source_format": "docx",
                          "sha256_original": "a" * 64, "sha256_converted": "b" * 64}]}
    pdf = esign_pdf.certificate(env)
    from pypdf import PdfReader
    text = " ".join((pg.extract_text() or "") for pg in PdfReader(io.BytesIO(pdf)).pages).replace("\n", " ")
    assert "b" * 20 in text.replace(" ", "") and "PDF signers saw" in text
