"""E-Sign key ceremony: create an offline PKI (root -> issuing CA -> document seal) into a private directory.

You don't need this to get started: with no ESIGN_SEAL_P12 set, the server generates a self-signed root + seal in
DATA_DIR/pki on first use. Use this script when you want the ROOT key kept off the server (only the seal goes on it),
or to rotate the seal.

    python scripts/esign_pki.py <out_dir>            # creates the hierarchy
    python scripts/esign_pki.py <out_dir> --reseal   # new seal certificate from the existing issuing CA (rotation)

Set ESIGN_BRAND_LEGAL_NAME (or ESIGN_BRAND_NAME) first: it names the certificates ("<name> E-Sign Root CA", …).

Writes (mode 0600, nothing secret is printed):
  root_ca.key.pem + root_ca.pass   the ROOT private key (encrypted) and its passphrase -> keep OFFLINE, never on the
                                   server
  root_ca.crt                      the root certificate (public; also served by the server at /v1/sign/root.crt)
  issuing_ca.key.pem + issuing_ca.pass + issuing_ca.crt   kept so the seal can be re-issued without the root
  seal.p12.b64 + seal.pass         -> server env ESIGN_SEAL_P12 (the base64 text, or a path to this file) and
                                      ESIGN_SEAL_PASS
  fingerprints.txt                 SHA-256 fingerprints of the three certificates (public)

After a rotation (--reseal), add the OLD seal's fingerprint to ESIGN_SEAL_FPS (comma-separated) so documents sealed
before the rotation still verify as yours.
"""
import base64
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from esign import esign_pki as K  # noqa: E402


def _w(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _pw() -> bytes:
    return secrets.token_urlsafe(32).encode()


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    if "--reseal" in sys.argv:
        ca_pass = (out / "issuing_ca.pass").read_bytes()
        ca_key = serialization.load_pem_private_key((out / "issuing_ca.key.pem").read_bytes(), ca_pass)
        ca = x509.load_pem_x509_certificate((out / "issuing_ca.crt").read_bytes())
        root = x509.load_pem_x509_certificate((out / "root_ca.crt").read_bytes())
    else:
        if (out / "root_ca.key.pem").exists():
            sys.exit(f"{out} already holds a root key; refusing to overwrite (use --reseal to rotate the seal)")
        root_pass = _pw()
        root_key, root = K.make_root()
        ca_key, ca = K.make_issuing_ca(root_key, root)
        ca_pass = _pw()
        _w(out / "root_ca.pass", root_pass)
        _w(out / "root_ca.key.pem", K.key_pem(root_key, root_pass))
        _w(out / "root_ca.crt", K.pem(root))
        _w(out / "issuing_ca.pass", ca_pass)
        _w(out / "issuing_ca.key.pem", K.key_pem(ca_key, ca_pass))
        _w(out / "issuing_ca.crt", K.pem(ca))
        del root_key
    seal_key, seal = K.make_seal(ca_key, ca)
    seal_pass = _pw()
    _w(out / "seal.pass", seal_pass)
    _w(out / "seal.p12.b64", base64.b64encode(K.to_p12(seal_key, seal, [ca, root], seal_pass)))
    fps = "\n".join(f"{n}: {c.fingerprint(hashes.SHA256()).hex()}  (valid to {c.not_valid_after_utc:%Y-%m-%d})"
                    for n, c in (("root", root), ("issuing", ca), ("seal", seal)))
    _w(out / "fingerprints.txt", (fps + "\n").encode())
    print(f"written to {out} (mode 0600)\n{fps}")


if __name__ == "__main__":
    main()
