# Daertho E-Sign

Self-hosted e-signatures you can put your own name on. Send PDFs (or Word files) for signature, track every step, and get back a sealed, timestamped PDF that any PDF reader can check. It runs on your server with your database, and your documents never leave them. There are no per-seat fees.

Apache-2.0. One Docker container. SQLite by default, Postgres if you want it.

## What it does

- **Envelopes.** Upload up to 20 documents (PDF, PNG/JPEG, or Word/ODT/RTF, which are converted with LibreOffice). Add signers, CC and viewers, set a routing order, and drag fields onto the page: signature, initials, date signed, name, email, company, title, text, checkbox, date.
- **Signing links.** Each recipient gets their own HMAC-signed link. Nothing secret is stored, and regenerating a link kills the old one immediately. You can add an access code per recipient, or a one-time code sent by email.
- **Email or not.** With SMTP configured, the app emails invitations, reminders, void notices and the signed copy. Without it, you copy each link and share it however you like.
- **Audit trail.** An append-only, SHA-256 hash-chained log of every event (sent, viewed, consented, signed, declined, voided, corrected). A Certificate of Completion is appended to the final PDF.
- **Tamper-evident seal.** Every completed PDF gets a PAdES digital seal plus an RFC 3161 timestamp from an independent timestamp authority. Adobe Reader and other PDF tools show whether the file has changed since it was sealed. A built-in **Verify** page checks any PDF you upload.
- **White-label.** Your name, logo, colours and fonts on the sender app, the signer page, the emails, the seal and the certificate.
- **Teams.** Admins add users. Each user sees only their own envelopes. Per-user API keys cover automation, and OpenAPI docs are at `/api/docs`.
- **Records stay records.** Sent envelopes can be voided but not deleted. Optionally, every stored file is encrypted at rest.

## Quick start (Docker)

```bash
git clone https://github.com/<you>/daertho-esign && cd daertho-esign
cp .env.example .env
```

Set `ESIGN_SECRET` (run `openssl rand -hex 32`) and `ESIGN_PUBLIC_URL` in `.env`, then:

```bash
docker compose up -d
```

Open http://localhost:8000. The first visit asks you to create the admin account.

## One-click hosting

| Host | How |
|---|---|
| **Render** | Fork this repo, then *New → Blueprint* and pick your fork. `render.yaml` sets up the service, a 5 GB disk at `/data`, and a generated `ESIGN_SECRET`. Then set `ESIGN_PUBLIC_URL`. |
| **Railway** | *New project → Deploy from GitHub repo*. `railway.json` builds the Dockerfile. Add a **volume mounted at `/data`** and set `ESIGN_SECRET`, `ESIGN_PUBLIC_URL` and `ESIGN_TRUST_PROXY=1`. |
| **Any VM** | Docker Compose as above, behind Caddy or nginx for HTTPS. Set `ESIGN_TRUST_PROXY=1`. |

Run **one** instance with **one** worker. Envelope edits are serialised in-process. (With Postgres, a single instance is still the supported setup.)

## Configuration

Everything is an environment variable. `.env.example` lists all of them with comments. The important ones:

| Variable | What it does |
|---|---|
| `ESIGN_SECRET` | Signs sessions and signing links. Required in production. Changing it signs everyone out and invalidates every unsigned link. |
| `ESIGN_PUBLIC_URL` | The address people reach the app on. Used in emailed links. |
| `ESIGN_DATABASE_URL` | Empty means SQLite in `ESIGN_DATA_DIR`. `postgresql://…` means Postgres. |
| `ESIGN_ENC_KEY` | Optional Fernet key that encrypts every stored file. **Back it up**: lose it and the files are gone. |
| `ESIGN_MAIL`, `ESIGN_SMTP_*` | Turn on emailed links (any SMTP provider: SES, Postmark, Resend, Google Workspace, Mailgun…). |
| `ESIGN_SEAL_P12`, `ESIGN_SEAL_PASS` | Your own seal certificate. If empty, one is generated on first boot (see below). |
| `ESIGN_TSA_URLS` | Timestamp servers. Defaults to free public ones. `off` disables timestamping. |
| `ESIGN_BRAND_*` | Name, legal name, logo URL, accent/background/ink colours, Google Font families, support email, and whether to hide "Powered by". |

### The seal certificate

On first boot, if no seal is configured, the app creates a private root CA and a seal certificate in `$ESIGN_DATA_DIR/pki` (keys encrypted, mode 0700). Sealed PDFs are tamper-evident right away. PDF readers will say the signer is *unknown* until the root is trusted: download it from `/v1/sign/root.crt` and import it, or:

- use `scripts/esign_pki.py` to make a root you keep **offline** and a seal certificate for the server, or
- buy a document-signing certificate from a CA on the Adobe Approved Trust List (AATL) and set `ESIGN_SEAL_P12`. Readers then show a green tick everywhere.

If you rotate the seal, add the old certificate's fingerprint to `ESIGN_SEAL_FPS` so earlier PDFs still verify.

## Legal standing

Signatures made here are **simple electronic signatures** with strong evidence: intent, consent to electronic records, a per-signer link, optional access/email codes, a hash-chained audit trail, and a sealed and timestamped final PDF. That is enough for most commercial agreements under the US ESIGN Act / UETA and the EU eIDAS Regulation. It is **not** a qualified electronic signature (QES). Some documents (certain property, family-law and notarised deeds, depending on the country) need more. Check what your use case requires.

## Backups

Back up `ESIGN_DATA_DIR` (the SQLite file and `pki/`), or your Postgres database plus `pki/`, and keep `ESIGN_SECRET` and `ESIGN_ENC_KEY` somewhere safe.

## Admin commands

```bash
docker compose exec esign python -m esign.cli create-admin you@example.com
```

```bash
docker compose exec esign python -m esign.cli reset-password you@example.com
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
.venv/bin/uvicorn esign.main:app --reload
```

```bash
.venv/bin/pytest -q
```

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). Please don't open public issues for them.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The name "Daertho" and its logo are trademarks and aren't covered by the licence. When you white-label, use your own brand.
