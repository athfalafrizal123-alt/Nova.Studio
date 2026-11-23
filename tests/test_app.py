import http.cookiejar
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

import app


class AuthenticationFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.NovaRequestHandler)
        cls.server.daemon_threads = True
        cls.origin = "http://127.0.0.1:{}".format(cls.server.server_address[1])
        app.APP_ORIGIN = cls.origin
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        app.DATABASE_PATH = Path(self.temp_directory.name) / "test.sqlite3"
        self.original_cookie_secure = app.COOKIE_SECURE
        app.COOKIE_SECURE = False
        app.initialize_database()
        cookies = http.cookiejar.CookieJar()
        self.client = build_opener(HTTPCookieProcessor(cookies))

    def tearDown(self):
        app.COOKIE_SECURE = self.original_cookie_secure
        self.temp_directory.cleanup()

    def request(self, path, method="GET", payload=None, origin=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if method == "POST":
            headers["Origin"] = self.origin if origin is None else origin
        request = Request(self.origin + path, data=data, headers=headers, method=method)
        try:
            response = self.client.open(request, timeout=3)
        except HTTPError as error:
            response = error
        return response.code, json.loads(response.read().decode("utf-8")), response.headers

    def test_registration_persists_hash_and_session_can_be_revoked(self):
        status, result, headers = self.request(
            "/api/register",
            method="POST",
            payload={"email": "Studio@Example.com", "password": "a-long-demo-password"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(result["user"]["email"], "studio@example.com")
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])

        with app.database() as connection:
            row = connection.execute(
                "SELECT email, password_hash FROM users WHERE email = ?",
                ("studio@example.com",),
            ).fetchone()
        self.assertNotEqual(row["password_hash"], "a-long-demo-password")
        self.assertTrue(app.verify_password("a-long-demo-password", row["password_hash"]))

        status, result, _ = self.request("/api/me")
        self.assertEqual(status, 200)
        self.assertEqual(result["user"]["email"], "studio@example.com")

        status, _, _ = self.request("/api/logout", method="POST", payload={})
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/me")
        self.assertEqual(status, 401)

    def test_login_rejects_wrong_password_and_accepts_correct_password(self):
        self.request(
            "/api/register",
            method="POST",
            payload={"email": "user@example.com", "password": "another-long-password"},
        )
        status, result, _ = self.request(
            "/api/login",
            method="POST",
            payload={"email": "user@example.com", "password": "incorrect-password"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(result["error"], "Email atau kata sandi salah.")

        status, result, _ = self.request(
            "/api/login",
            method="POST",
            payload={"email": "user@example.com", "password": "another-long-password"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["user"]["email"], "user@example.com")

    def test_registration_rejects_weak_password_and_cross_origin_request(self):
        status, _, _ = self.request(
            "/api/register",
            method="POST",
            payload={"email": "weak@example.com", "password": "short"},
        )
        self.assertEqual(status, 400)

        status, _, _ = self.request(
            "/api/register",
            method="POST",
            payload={"email": "other@example.com", "password": "a-long-demo-password"},
            origin="https://attacker.example",
        )
        self.assertEqual(status, 403)
        with app.database() as connection:
            count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(count, 0)

    def test_https_session_cookie_is_secure(self):
        original_cookie_secure = app.COOKIE_SECURE
        try:
            app.COOKIE_SECURE = True
            self.assertIn("; Secure", app.session_cookie("random-token"))
        finally:
            app.COOKIE_SECURE = original_cookie_secure


if __name__ == "__main__":
    unittest.main()
