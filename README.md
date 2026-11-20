# Daertho E-Sign

Self-hosted e-signatures you can put your own name on. Send PDFs (or Word files) for signature, track every step, and get back a sealed, timestamped PDF that any PDF reader can check. It runs on your server with your database, and your documents never leave them. There are no per-seat fees.

Apache-2.0. One Docker container. SQLite by default, Postgres if you want it.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/sect0rial/daertho-esign)

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

Open http://localhost:8000. The first visit asks you to create the admin account, and for a **setup token** that proves the server is yours. Set `ESIGN_SETUP_TOKEN` in `.env` to choose it. If you leave it empty, the server makes one up and writes it to its log at start-up:

```bash
docker compose logs esign | grep "Setup token"
```

The token is only used once. After the admin account exists, first-run setup is closed for good.

## One-click hosting

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/sect0rial/daertho-esign)

| Host | How |
|---|---|
| **Render** | Click the button above. Render reads `render.yaml`, creates the service with a 5 GB disk at `/data`, and generates `ESIGN_SECRET` and `ESIGN_SETUP_TOKEN`. It asks you for `ESIGN_PUBLIC_URL` (your app's address, such as `https://your-app.onrender.com`) and, optionally, your brand name and an encryption key. The disk needs a paid plan (Starter or above). When the app is up, copy `ESIGN_SETUP_TOKEN` from the service's *Environment* page in the Render dashboard: the first-run page asks for it before it creates your admin account. To run your own changes, fork the repo first and use *New → Blueprint* on your fork. |
| **Railway** | *New project → Deploy from GitHub repo*. `railway.json` builds the Dockerfile. Add a **volume mounted at `/data`** and set `ESIGN_SECRET`, `ESIGN_PUBLIC_URL` and `ESIGN_TRUST_PROXY=1` under *Variables*. Also set `ESIGN_SETUP_TOKEN` there to a long random string (`openssl rand -hex 16`) and type it on the first-run page. If you leave it out, copy the token the app prints in its deploy log. |
| **Any VM** | Docker Compose as above, behind Caddy or nginx for HTTPS. Set `ESIGN_TRUST_PROXY=1`. |

Run **one** instance with **one** worker. Envelope edits are serialised in-process. (With Postgres, a single instance is still the supported setup.)

## Configuration

Everything is an environment variable. `.env.example` lists all of them with comments. The important ones:

| Variable | What it does |
|---|---|
| `ESIGN_SECRET` | Signs sessions and signing links. Required in production. Changing it signs everyone out and invalidates every unsigned link. |
| `ESIGN_PUBLIC_URL` | The address people reach the app on. Used in emailed links. |
| `ESIGN_SETUP_TOKEN` | Asked for once, on the first-run page, before the first admin account is created (16 characters or more). If unset, a random token is written to the server log and to `ESIGN_DATA_DIR/.setup-token`. It has no use after setup. |
| `ESIGN_DATABASE_URL` | Empty means SQLite in `ESIGN_DATA_DIR`. `postgresql://…` means Postgres. |
| `ESIGN_ENC_KEY` | Optional Fernet key that encrypts every stored file. **Back it up**: lose it and the files are gone. |
| `ESIGN_MAIL`, `ESIGN_SMTP_*` | Turn on emailed links (any SMTP provider: SES, Postmark, Resend, Google Workspace, Mailgun…). |
| `ESIGN_SEAL_P12`, `ESIGN_SEAL_PASS` | Your own seal certificate. If empty, one is generated on first boot (see below). |
| `ESIGN_TSA_URLS` | Timestamp servers. Defaults to free public ones. `off` disables timestamping. |
| `ESIGN_MAX_BODY_MB`, `ESIGN_VERIFY_MAX_MB` | Request-size limits, in megabytes (see below). Defaults: 8 and 500. |
| `ESIGN_BRAND_*` | Name, legal name, logo URL, accent/background/ink colours, Google Font families, support email, and whether to hide "Powered by". |

### Request-size limits

The app refuses a request that is too large before it reads it, and on the owner routes it checks the sign-in before it reads an upload, so a stranger cannot fill the disk with uploads that would have been refused anyway.

| Request | Limit |
|---|---|
| Document upload (signed in) | 25 MB per file |
| Verify a PDF (signed in) | `ESIGN_VERIFY_MAX_MB`, default 500 MB. Files above 60 MB are hash-checked only. |
| Sign-in, setup, users, API keys | 64 KB |
| Everything else, including the signer's submission | `ESIGN_MAX_BODY_MB`, default 8 MB. Don't go below 7: a signer's drawn signatures can take up to 6 MB. |

If you run a reverse proxy in front, set its own limit too, so oversized requests are dropped at the edge. For nginx that is `client_max_body_size 501m;` (or lower if you lowered `ESIGN_VERIFY_MAX_MB`). Caddy has `request_body { max_size 501MB }`.

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

On a fresh install, this prints the setup token the first-run page asks for:

```bash
docker compose exec esign python -m esign.cli setup-token
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

## Upgrading

Changes that need a moment of your attention when you pull a newer version:

- **First-run setup needs a token.** `POST /v1/auth/setup` now answers 403 without the setup token (`setup_token` in the JSON body). Before this, the first visitor to a fresh deployment could create the admin account. Servers that already have an account are not affected. For a new one, set `ESIGN_SETUP_TOKEN` or read the token from the start-up log.
- **Sign-in limits count by the real client address.** With `ESIGN_TRUST_PROXY=1` the sign-in and first-run limits now use the last `X-Forwarded-For` hop (the one your proxy wrote), the same rule the signer evidence already used. Before this they used the first hop, which the client controls. Wrong passwords are now counted per account *and* address (10 in 15 minutes), so somebody who knows a user's email can no longer lock that user out. Nothing to change in your settings, but check that your proxy really is the only way to reach the app.
- **Request-size limits.** Requests above the limits in [Request-size limits](#request-size-limits) now get 413 before they are read, and an upload to an owner route gets 401 before it is read if the caller isn't signed in. If you post JSON bodies above 8 MB to the API, raise `ESIGN_MAX_BODY_MB`.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). Please don't open public issues for them.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The name "Daertho" and its logo are trademarks and aren't covered by the licence. When you white-label, use your own brand.
