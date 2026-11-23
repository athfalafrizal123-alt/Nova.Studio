# Nova Studio

Nova Studio is a static front end served by a small Python backend. The backend stores accounts and hashed passwords in SQLite and issues expiring, HttpOnly session cookies.

## Run locally over HTTPS

Requires Python 3.9 or newer and OpenSSL. Create a self-signed certificate for local development from PowerShell:

```powershell
New-Item -ItemType Directory -Force .certs | Out-Null
$env:OPENSSL_CONF = $null
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -keyout .certs/localhost-key.pem -out .certs/localhost.pem -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

If PowerShell cannot find `openssl`, install OpenSSL and reopen the terminal before continuing.

Configure the certificate and start the backend:

```powershell
$env:NOVA_TLS_CERT = "$PWD\.certs\localhost.pem"
$env:NOVA_TLS_KEY = "$PWD\.certs\localhost-key.pem"
python app.py
```

Open <https://127.0.0.1:8000>. A self-signed certificate may trigger a browser warning; it is only for local development. Do not open `index.html` directly: the authentication endpoints need the HTTPS backend. The SQLite database is created at `.data/nova.sqlite3` on first run.

To run the tests:

```powershell
python -m unittest discover -s tests -v
```

## Security notes

- Passwords are hashed with PBKDF2-HMAC-SHA256; plaintext passwords are never stored.
- Session tokens are random, stored in the database only as SHA-256 digests, and expire after 12 hours.
- Authentication endpoints require a same-origin request and have per-IP attempt limits.
- HTTPS is required. The server uses TLS 1.2 or newer and sets the session cookie `Secure` attribute.
- The server binds to `127.0.0.1` by default and is intended for local development, not direct public deployment.
- The portfolio content is still public. Login does not protect static files or make any existing section private.
- For a public deployment, use a production-grade application server behind HTTPS and set `NOVA_APP_ORIGIN` to the exact public origin. Keep the SQLite database on persistent, access-restricted storage and back it up securely.

Configuration:

- `NOVA_HOST` and `NOVA_PORT` change the local bind address and port.
- `NOVA_DB_PATH` changes the SQLite database path.
- `NOVA_APP_ORIGIN` sets the exact allowed HTTPS browser origin (default: `https://127.0.0.1:8000`).
- `NOVA_TLS_CERT` and `NOVA_TLS_KEY` must point to the TLS certificate and private key.
