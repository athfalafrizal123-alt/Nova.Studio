import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import time
import uuid
from contextlib import contextmanager
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.environ.get("NOVA_DB_PATH", ROOT / ".data" / "nova.sqlite3")).resolve()
APP_HOST = os.environ.get("NOVA_HOST", "127.0.0.1")
APP_PORT = int(os.environ.get("NOVA_PORT", "8000"))
TLS_CERT_FILE = os.environ.get("NOVA_TLS_CERT")
TLS_KEY_FILE = os.environ.get("NOVA_TLS_KEY")
TLS_ENABLED = bool(TLS_CERT_FILE and TLS_KEY_FILE)
APP_ORIGIN = os.environ.get(
    "NOVA_APP_ORIGIN",
    f"https://127.0.0.1:{APP_PORT}",
).rstrip("/")
COOKIE_SECURE = True
COOKIE_NAME = "nova_session"
SESSION_SECONDS = 12 * 60 * 60
PASSWORD_ITERATIONS = 600_000
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
MAX_REQUEST_BYTES = 16 * 1024
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
SESSION_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
RATE_LIMITS = {"login": (8, 15 * 60), "register": (5, 60 * 60)}


class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


@contextmanager
def database():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS auth_attempts (
                ip_hash TEXT NOT NULL,
                action TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                window_started INTEGER NOT NULL,
                blocked_until INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ip_hash, action)
            );
            """
        )


def normalize_email(value):
    if not isinstance(value, str):
        raise RequestError(400, "Masukkan alamat email yang valid.")
    email = value.strip().casefold()
    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        raise RequestError(400, "Masukkan alamat email yang valid.")
    return email


def validate_password(value, registration=False):
    if not isinstance(value, str):
        raise RequestError(400, "Masukkan kata sandi.")
    if registration and len(value) < PASSWORD_MIN_LENGTH:
        raise RequestError(400, f"Kata sandi harus memiliki minimal {PASSWORD_MIN_LENGTH} karakter.")
    if not value or len(value) > PASSWORD_MAX_LENGTH:
        raise RequestError(400, f"Kata sandi harus memiliki 1–{PASSWORD_MAX_LENGTH} karakter.")
    return value


def hash_password(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        salt.hex(),
        derived.hex(),
    )


def verify_password(password, encoded_hash):
    try:
        algorithm, iterations_text, salt_hex, expected_hex = encoded_hash.split("$")
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 1_000_000:
            raise ValueError("Unsupported password hash.")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except (AttributeError, TypeError, ValueError):
        hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b"\0" * 16, PASSWORD_ITERATIONS)
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def client_key(client_ip):
    return hashlib.sha256(client_ip.encode("utf-8")).hexdigest()


def rate_limit_remaining(ip_hash, action):
    now = int(time.time())
    with database() as connection:
        row = connection.execute(
            "SELECT blocked_until FROM auth_attempts WHERE ip_hash = ? AND action = ?",
            (ip_hash, action),
        ).fetchone()
    return max(0, row["blocked_until"] - now) if row else 0


def record_attempt(ip_hash, action):
    limit, window_seconds = RATE_LIMITS[action]
    now = int(time.time())
    with database() as connection:
        row = connection.execute(
            "SELECT attempts, window_started FROM auth_attempts WHERE ip_hash = ? AND action = ?",
            (ip_hash, action),
        ).fetchone()
        if row is None or now - row["window_started"] >= window_seconds:
            attempts = 1
            window_started = now
        else:
            attempts = row["attempts"] + 1
            window_started = row["window_started"]
        blocked_until = now + window_seconds if attempts >= limit else 0
        connection.execute(
            """
            INSERT INTO auth_attempts (ip_hash, action, attempts, window_started, blocked_until)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip_hash, action) DO UPDATE SET
                attempts = excluded.attempts,
                window_started = excluded.window_started,
                blocked_until = excluded.blocked_until
            """,
            (ip_hash, action, attempts, window_started, blocked_until),
        )
        connection.execute(
            "DELETE FROM auth_attempts WHERE window_started < ?",
            (now - 24 * 60 * 60,),
        )
    return max(0, blocked_until - now)


def clear_attempts(ip_hash, action):
    with database() as connection:
        connection.execute(
            "DELETE FROM auth_attempts WHERE ip_hash = ? AND action = ?",
            (ip_hash, action),
        )


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_digest(token), user_id, now, now + SESSION_SECONDS),
        )
    return token


def session_cookie(token):
    cookie = f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
    return cookie + ("; Secure" if COOKIE_SECURE else "")


def cleared_session_cookie():
    cookie = f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    return cookie + ("; Secure" if COOKIE_SECURE else "")


class NovaRequestHandler(BaseHTTPRequestHandler):
    server_version = "NovaStudio"
    sys_version = ""

    def log_message(self, format_string, *args):
        if self.path.startswith("/api/"):
            return
        super().log_message(format_string, *args)

    def send_headers(self, content_type, content_length, cache_control="no-store"):
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'",
        )

    def send_json(self, status, payload, cookie=None, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_headers("application/json; charset=utf-8", len(body))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_request_error(self, error):
        self.send_json(error.status, {"error": str(error)})

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            raise RequestError(415, "Permintaan harus menggunakan JSON.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise RequestError(400, "Ukuran permintaan tidak valid.") from None
        if length < 0:
            raise RequestError(400, "Ukuran permintaan tidak valid.")
        if length > MAX_REQUEST_BYTES:
            raise RequestError(413, "Permintaan terlalu besar.")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestError(400, "Format JSON tidak valid.") from None
        if not isinstance(payload, dict):
            raise RequestError(400, "Format permintaan tidak valid.")
        return payload

    def request_origin_is_valid(self):
        return self.headers.get("Origin") == APP_ORIGIN

    def read_session_token(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookies.get(COOKIE_NAME)
        token = morsel.value if morsel else None
        return token if token and SESSION_TOKEN_PATTERN.fullmatch(token) else None

    def current_user(self):
        token = self.read_session_token()
        if not token:
            return None
        now = int(time.time())
        with database() as connection:
            row = connection.execute(
                """
                SELECT users.id, users.email, sessions.expires_at
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ?
                """,
                (token_digest(token),),
            ).fetchone()
            if row and row["expires_at"] <= now:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
                return None
        return {"id": row["id"], "email": row["email"]} if row else None

    def user_response(self, status, user_id, email):
        token = create_session(user_id)
        self.send_json(status, {"user": {"email": email}}, cookie=session_cookie(token))

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/me":
            user = self.current_user()
            if user is None:
                self.send_json(401, {"error": "Belum masuk."})
                return
            self.send_json(200, {"user": {"email": user["email"]}})
            return
        if path not in ("/", "/index.html"):
            self.send_json(404, {"error": "Halaman tidak ditemukan."})
            return

        page = (ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_headers("text/html; charset=utf-8", len(page))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/api/register", "/api/login", "/api/logout"):
            self.send_json(404, {"error": "Endpoint tidak ditemukan."})
            return
        if not self.request_origin_is_valid():
            self.send_json(403, {"error": "Permintaan lintas-origin ditolak."})
            return
        if path == "/api/logout":
            token = self.read_session_token()
            if token:
                with database() as connection:
                    connection.execute(
                        "DELETE FROM sessions WHERE token_hash = ?",
                        (token_digest(token),),
                    )
            self.send_json(200, {"ok": True}, cookie=cleared_session_cookie())
            return
        try:
            payload = self.read_json()
            email = normalize_email(payload.get("email"))
            password = validate_password(
                payload.get("password"),
                registration=path == "/api/register",
            )
        except RequestError as error:
            self.send_request_error(error)
            return

        ip_hash = client_key(self.client_address[0])
        action = "register" if path == "/api/register" else "login"
        retry_after = rate_limit_remaining(ip_hash, action)
        if retry_after:
            self.send_json(
                429,
                {"error": "Terlalu banyak percobaan. Coba lagi nanti."},
                extra_headers={"Retry-After": str(retry_after)},
            )
            return

        if path == "/api/register":
            record_attempt(ip_hash, action)
            user_id = uuid.uuid4().hex
            try:
                with database() as connection:
                    connection.execute(
                        "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                        (user_id, email, hash_password(password), int(time.time())),
                    )
            except sqlite3.IntegrityError:
                self.send_json(409, {"error": "Email tersebut sudah terdaftar."})
                return
            self.user_response(201, user_id, email)
            return

        with database() as connection:
            user = connection.execute(
                "SELECT id, email, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        password_is_valid = verify_password(password, user["password_hash"] if user else None)
        if user is None or not password_is_valid:
            retry_after = record_attempt(ip_hash, action)
            if retry_after:
                self.send_json(
                    429,
                    {"error": "Terlalu banyak percobaan. Coba lagi nanti."},
                    extra_headers={"Retry-After": str(retry_after)},
                )
                return
            self.send_json(401, {"error": "Email atau kata sandi salah."})
            return

        clear_attempts(ip_hash, action)
        self.user_response(200, user["id"], user["email"])


def main():
    if bool(TLS_CERT_FILE) != bool(TLS_KEY_FILE):
        raise ValueError("Set both NOVA_TLS_CERT and NOVA_TLS_KEY to enable HTTPS.")
    if not TLS_ENABLED:
        raise ValueError("HTTPS is required. Set NOVA_TLS_CERT and NOVA_TLS_KEY before starting.")
    origin = urlsplit(APP_ORIGIN)
    if (
        origin.scheme != "https"
        or not origin.netloc
        or origin.path
        or origin.query
        or origin.fragment
        or origin.username
        or origin.password
    ):
        raise ValueError("NOVA_APP_ORIGIN must be an https origin without a path.")
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    initialize_database()
    server = ThreadingHTTPServer((APP_HOST, APP_PORT), NovaRequestHandler)
    server.daemon_threads = True
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    print(f"Nova Studio berjalan di {APP_ORIGIN}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
