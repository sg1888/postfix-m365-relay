#!/usr/bin/env python3
"""Offline unit tests for the two credential-bearing Python helpers.

Run inside the built image via python-unit.sh so tests exercise the exact
cryptography/OpenSSL stack shipped to users. Network calls are replaced with
recording fakes; these tests must never contact Microsoft or require a tenant.
"""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def load_module(name: str, relative_path: str):
    """Import a command whose hyphenated filename is not a Python identifier."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


refresh = load_module("refresh_smtp_token", "scripts/refresh-smtp-token.py")
rotate = load_module("rotate_smtp_relay_cert", "scripts/rotate-smtp-relay-cert.py")
qualify = load_module("qualify_relay", "scripts/qualify-relay.py")


def decode_segment(segment: str) -> dict:
    """Decode one unpadded JWT segment for structural assertions."""
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class CertificateTests(unittest.TestCase):
    def test_certificate_role_parameters_are_honored(self):
        from cryptography.x509.oid import NameOID

        key, cert = rotate.make_certificate(10, 2048, "Inbound [Test]")
        self.assertEqual(key.key_size, 2048)
        self.assertEqual(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Inbound [Test]",
        )
        # Whole-day flooring plus a five-minute backdate yields 9 or 10 days.
        self.assertIn(rotate.days_remaining(cert), (9, 10))

    def test_certificate_can_be_renewed_with_the_same_private_key(self):
        """Inbound renewal changes the certificate, not its stable key."""
        key, first = rotate.make_certificate(2, 2048, "Relay TLS")
        reused_key, second = rotate.make_certificate(20, 2048, "Relay TLS", key)
        self.assertIs(reused_key, key)
        self.assertEqual(
            second.public_key().public_numbers(), key.public_key().public_numbers()
        )
        self.assertNotEqual(first.serial_number, second.serial_number)
        self.assertGreater(rotate.days_remaining(second), rotate.days_remaining(first))

    def test_graph_thumbprints_accept_documented_and_observed_encodings(self):
        raw = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF01234567")
        expected = raw.hex().upper()
        self.assertEqual(rotate.credential_thumbprint({"customKeyIdentifier": expected}), expected)
        self.assertEqual(
            rotate.credential_thumbprint(
                {"customKeyIdentifier": base64.b64encode(raw).decode()}
            ),
            expected,
        )
        self.assertEqual(rotate.credential_thumbprint({"customKeyIdentifier": "not-a-thumbprint"}), "")

    def test_rotation_refuses_inbound_and_non_secret_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_env = {
                "MAIL_RELAY_TENANT": "tenant",
                "MAIL_RELAY_CLIENT_ID": "client",
                "MAIL_SEND_MAILBOX": "relay@example.invalid",
            }
            for parent in ("inbound-tls", "other"):
                env = base_env | {
                    "MAIL_RELAY_KEY_FILE": str(root / parent / "key.pem"),
                    "MAIL_RELAY_CERT_FILE": str(root / parent / "cert.pem"),
                }
                with self.subTest(parent=parent), self.assertRaises(ValueError):
                    rotate.Rotation(root, env, root / "rotation.log", True)


class AssertionAndTokenTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization

        self.key, self.cert = rotate.make_certificate(2, 2048, "JWT test")
        self.key_pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)

    def test_client_assertion_claims_thumbprint_and_signature(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        with mock.patch.object(refresh.time, "time", return_value=1_700_000_000):
            assertion = refresh.client_assertion("tenant-id", "client-id", self.key_pem, self.cert_pem)
        header_segment, claims_segment, signature_segment = assertion.split(".")
        header = decode_segment(header_segment)
        claims = decode_segment(claims_segment)
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["x5t"], refresh.b64url(self.cert.fingerprint(hashes.SHA1())))
        self.assertEqual(claims["aud"], f"{refresh.LOGIN}/tenant-id/oauth2/v2.0/token")
        self.assertEqual(claims["iss"], "client-id")
        self.assertEqual(claims["sub"], "client-id")
        self.assertEqual(claims["nbf"], 1_699_999_940)
        self.assertEqual(claims["exp"], 1_700_000_600)
        signature = base64.urlsafe_b64decode(signature_segment + "=" * (-len(signature_segment) % 4))
        self.key.public_key().verify(
            signature,
            f"{header_segment}.{claims_segment}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def test_token_request_uses_outlook_scope_and_client_credentials(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"access_token":"safe-test-token","expires_in":3210}'

        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse()

        with mock.patch.object(refresh.urllib.request, "urlopen", side_effect=fake_urlopen):
            token, lifetime = refresh.request_token("tenant", "client", "assertion")
        body = refresh.urllib.parse.parse_qs(captured["request"].data.decode())
        self.assertEqual(captured["request"].full_url, f"{refresh.LOGIN}/tenant/oauth2/v2.0/token")
        self.assertEqual(body["scope"], [refresh.OUTLOOK_SCOPE])
        self.assertEqual(body["grant_type"], ["client_credentials"])
        self.assertEqual((token, lifetime, captured["timeout"]), ("safe-test-token", 3210, 30))

    def test_token_file_is_atomic_private_and_truthful(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relay.json"
            with mock.patch.object(refresh.time, "time", return_value=1_700_000_000):
                expiry = refresh.write_token_file(path, "safe-test-token", 3600)
            payload = json.loads(path.read_text())
            self.assertEqual(expiry, 1_700_003_600)
            self.assertEqual(payload["expiry"], "1700003600")
            self.assertEqual(payload["access_token"], "safe-test-token")
            self.assertIn("unused-app-only", payload["refresh_token"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(path.with_suffix(".tmp").exists())


class EnvFileTests(unittest.TestCase):
    def test_env_file_is_data_not_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("# comment\nA=one=two\nB=$(must-not-run)\nignored\n")
            self.assertEqual(
                refresh.read_env(path),
                {"A": "one=two", "B": "$(must-not-run)"},
            )


class QualificationClientTests(unittest.TestCase):
    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            self.calls = []
            self.message = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def ehlo(self):
            self.calls.append("ehlo")

        def starttls(self, context):
            self.calls.append("starttls")

        def login(self, username, password):
            self.calls.append(("login", username, password))

        def send_message(self, message):
            self.message = message

    def test_qualification_client_preserves_bracket_name_and_id(self):
        smtp = self.FakeSMTP()
        argv = [
            "qualify-relay.py", "--host", "relay", "--from-address",
            "app@relay.example.local", "--from-name", "MyServer [TestServer]",
            "--to", "recipient@example.invalid",
        ]
        with mock.patch.object(qualify.smtplib, "SMTP", return_value=smtp), \
                mock.patch.object(qualify.sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(qualify.main(), 0)
        # Brackets require an RFC quoted-string on the wire. The first test
        # expected unquoted raw text and failed even though the parsed display
        # name was correct; assert both layers so quoting regressions are visible.
        self.assertEqual(str(smtp.message["From"]), '"MyServer [TestServer]" <app@relay.example.local>')
        self.assertEqual(smtp.message["From"].addresses[0].display_name, "MyServer [TestServer]")
        self.assertTrue(smtp.message["Message-ID"].startswith("<qualification-"))

    def test_qualification_password_is_read_from_file_and_trimmed(self):
        smtp = self.FakeSMTP()
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "password"
            secret.write_text("file-only-secret\n")
            argv = [
                "qualify-relay.py", "--host", "relay", "--from-address",
                "app@relay.example.local", "--to", "recipient@example.invalid",
                "--starttls", "--username", "device", "--password-file", str(secret),
            ]
            with mock.patch.object(qualify.smtplib, "SMTP", return_value=smtp), \
                    mock.patch.object(qualify.sys, "argv", argv), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(qualify.main(), 0)
        self.assertIn("starttls", smtp.calls)
        self.assertIn(("login", "device", "file-only-secret"), smtp.calls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
