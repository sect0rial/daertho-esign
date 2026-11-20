# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately to **1@daertho.com**, or through GitHub's "Report a vulnerability" button on this repository. Include steps to reproduce. We aim to reply within 3 working days. Please don't open a public issue for a vulnerability.

## Supported versions

The `main` branch. There are no tagged releases yet, so fixes land on `main`. If you run a fork, pull from `main` to get them. The README has an [Upgrading](README.md#upgrading) section for changes that need your attention.

## What the app enforces

This is what the code does today. If you find it doing less, that is a bug we want to hear about.

**First run**
- The first admin account can only be created with the setup token (`ESIGN_SETUP_TOKEN`, or a random token written to the server log at start-up). The token is compared in constant time and is useless once an account exists.

**Accounts and sessions**
- Passwords are stored as scrypt hashes with a per-password salt. The minimum length is 10 characters.
- A browser session is an HMAC-signed cookie: `HttpOnly`, `SameSite=Lax`, and `Secure` when the app is served over HTTPS. Sessions last 14 days by default (`ESIGN_SESSION_DAYS`).
- Signing out ends that session on the server, so a copied cookie stops working. "Sign out everywhere", a password change, a password reset and disabling a user end every session that user has.
- Writes made with a session cookie must come from the app's own origin (the `Origin` header is checked).
- Sign-in is limited to 20 attempts per client address and 10 wrong passwords per account and address, in 15 minutes. An account is never locked for everyone: when it collects many wrong passwords from many addresses, addresses that have not signed in to it before are slowed to one attempt every 10 seconds.
- Changing a password is limited to 10 wrong "current password" entries in 15 minutes.
- API keys are shown once. Only a SHA-256 hash is stored. A key can be revoked by its owner at any time.
- Each user sees only their own envelopes.

**Signing links**
- Each recipient's link carries an HMAC over the envelope, the recipient and a link version. Regenerating a link makes the old one stop working at once, and a voided envelope can no longer be signed.
- Optional access codes and emailed one-time codes: 5 wrong entries lock the link for 15 minutes, and 20 in total lock it until the sender issues a new link. Emailed codes expire after 10 minutes and work once.
- The public signing routes are rate-limited per client address.

**Evidence**
- Every envelope event goes into an append-only log in which each entry includes the SHA-256 hash of the one before it.
- The completed PDF gets a PAdES seal and, unless you turn it off, an RFC 3161 timestamp.
- The signer's IP address is the TCP peer address, or the last `X-Forwarded-For` entry when `ESIGN_TRUST_PROXY=1`. See "Behind a reverse proxy" in the README: the setting has to match how the app is deployed.

**Requests and uploads**
- Request bodies are limited before they are read: 25 MB per uploaded document, 500 MB for a file sent to Verify, 64 KB on the account routes, 8 MB elsewhere. On the owner routes the sign-in is checked before an upload is read.
- Word, ODT and RTF files are converted by LibreOffice running as a separate unprivileged account that cannot read the app's code, data or environment (in the Docker image).
- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a `Referrer-Policy` and a `Permissions-Policy`, plus `Strict-Transport-Security` over HTTPS. The owner app is served with a Content-Security-Policy that allows scripts from the app's own origin only. The app sends no CORS headers, so other sites cannot read its API from a browser.

**Storage**
- With `ESIGN_ENC_KEY` set, every stored file is encrypted (Fernet). If the key is set but not valid, the server refuses to start. It never falls back to storing files unencrypted.
- The generated seal keys in `ESIGN_DATA_DIR/pki` are stored encrypted, in a directory with mode 0700.

## What it does not do

Decide whether these matter for your deployment.

- **API keys have no scopes and no expiry.** A key can do everything its user can do through the API, including creating more keys and, for an admin, more users. Treat a key like a password, and revoke keys you no longer use.
- **Signing links do not expire by themselves.** They stop working when the envelope is voided or the link is regenerated. After completion, the emailed link keeps giving access to the signed PDF for as long as `ESIGN_SECRET` stays the same.
- **No two-factor sign-in** for the people who send envelopes.
- **Access codes are stored as a single salted SHA-256 hash.** The attempt limits above protect them online. If your database leaks, short codes can be recovered quickly.
- **Rate limits are kept in memory** in the single app process. They reset when the app restarts.
- **The API docs page (`/api/docs`) loads Swagger UI from a public CDN.** Set `ESIGN_API_DOCS=0` if you don't want a third-party script on the app's origin.
- **The signer page uses inline script and styles**, so its Content-Security-Policy only forbids framing.
- **TLS is yours to provide.** The app speaks plain HTTP and expects a reverse proxy or your host's router in front for HTTPS.
- **The Docker base image is referenced by tag, not by digest.** Rebuild regularly to pick up base-image fixes.
