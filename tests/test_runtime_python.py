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
import sys
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
alert = load_module("alert_event", "scripts/alert-event.py")


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

    def test_pending_added_key_is_adopted_only_when_thumbprint_matches_live_cert(self):
        from cryptography.hazmat.primitives import hashes

        _key, cert = rotate.make_certificate(10, 2048, "Crash recovery")
        live_thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
        self.assertTrue(
            rotate.pending_addition_is_live(
                {"key_id": "new-key", "thumbprint": live_thumbprint}, cert
            )
        )
        self.assertFalse(
            rotate.pending_addition_is_live(
                {"key_id": "abandoned-key", "thumbprint": "00" * 20}, cert
            )
        )

    def test_rotation_state_persists_exact_pending_added_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state" / "rotation.json"
            env = {
                "MAIL_RELAY_TENANT": "tenant",
                "MAIL_RELAY_CLIENT_ID": "client",
                "MAIL_SEND_MAILBOX": "relay@example.invalid",
                "MAIL_RELAY_KEY_FILE": str(root / "secrets" / "key.pem"),
                "MAIL_RELAY_CERT_FILE": str(root / "secrets" / "cert.pem"),
                "MAIL_ROTATION_STATE_FILE": str(state_path),
            }
            rotation = rotate.Rotation(root, env, root / "rotation.log", False)
            expected = {
                "pending_addition": {
                    "key_id": "exact-added-key-id",
                    "thumbprint": "AB" * 20,
                    "added_at": 1_700_000_000,
                }
            }
            rotation.write_state(expected)
            self.assertEqual(rotation.read_state(), expected)
            self.assertFalse(state_path.with_suffix(".tmp").exists())

    def test_immediate_refresh_receives_file_loaded_configuration(self):
        env = {
            "MAIL_RELAY_TENANT": "tenant-from-file",
            "MAIL_RELAY_CLIENT_ID": "client-from-file",
            "MAIL_SEND_MAILBOX": "relay@example.invalid",
            "MAIL_RELAY_KEY_FILE": "/state/secrets/key.pem",
        }
        completed = mock.Mock(returncode=0)
        with mock.patch.object(rotate.subprocess, "run", return_value=completed) as run:
            self.assertTrue(
                rotate.run_immediate_token_refresh(
                    Path("/image/refresh-smtp-token.py"),
                    Path("/config/mail-relay.conf"),
                    env,
                )
            )
        command = run.call_args.args[0]
        child_env = run.call_args.kwargs["env"]
        self.assertEqual(
            command,
            [
                "/image/refresh-smtp-token.py",
                "--quiet",
                "--env-file",
                "/config/mail-relay.conf",
            ],
        )
        self.assertEqual(child_env["MAIL_RELAY_TENANT"], "tenant-from-file")
        self.assertEqual(child_env["MAIL_RELAY_CLIENT_ID"], "client-from-file")
        self.assertNotIn("PRIVATE KEY", " ".join(command))


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
            self.assertEqual(list(path.parent.glob(f".{path.name}.tmp.*")), [])

    def test_token_rename_failure_preserves_existing_good_file(self):
        """A failed atomic commit must not trade an outage for stale-but-valid mail."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relay.json"
            path.write_text('{"access_token":"existing-safe-token","expiry":"2000000000"}')
            with mock.patch.object(
                refresh.os,
                "replace",
                side_effect=OSError(30, "Read-only file system"),
            ):
                with self.assertRaisesRegex(refresh.TokenFileError, "Read-only file system"):
                    refresh.write_token_file(path, "new-safe-token", 3600)
            self.assertIn("existing-safe-token", path.read_text())
            self.assertNotIn("new-safe-token", path.read_text())
            self.assertEqual(list(path.parent.glob(f".{path.name}.tmp.*")), [])

    def test_token_open_permission_failure_is_concise_and_leaves_no_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relay.json"
            with mock.patch.object(
                refresh.os,
                "open",
                side_effect=PermissionError(13, "Permission denied"),
            ):
                with self.assertRaisesRegex(refresh.TokenFileError, "Permission denied") as caught:
                    refresh.write_token_file(path, "must-never-appear-in-error", 3600)
            self.assertNotIn("must-never-appear-in-error", str(caught.exception))
            self.assertFalse(path.exists())
            self.assertEqual(list(path.parent.glob(f".{path.name}.tmp.*")), [])

    def test_token_missing_parent_creation_failure_is_concise(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "uncreatable" / "relay.json"
            with mock.patch.object(
                refresh.Path,
                "mkdir",
                side_effect=OSError(13, "Permission denied"),
            ):
                with self.assertRaisesRegex(refresh.TokenFileError, "Permission denied"):
                    refresh.write_token_file(path, "safe-test-token", 3600)
            self.assertFalse(path.exists())

    def test_token_chown_failure_does_not_publish_root_only_staging_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relay.json"
            path.write_text('{"access_token":"existing-safe-token","expiry":"2000000000"}')
            with mock.patch.object(
                refresh.os,
                "chown",
                side_effect=PermissionError(1, "Operation not permitted"),
            ):
                with self.assertRaisesRegex(refresh.TokenFileError, "Operation not permitted"):
                    refresh.write_token_file(path, "new-safe-token", 3600, group=123)
            self.assertIn("existing-safe-token", path.read_text())
            self.assertEqual(list(path.parent.glob(f".{path.name}.tmp.*")), [])


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


class AlertIncidentTests(unittest.TestCase):
    def test_payload_has_reference_times_duration_guidance_and_redaction(self):
        incident = {
            "event": "token-health",
            "severity": "error",
            "reference_id": "PMR-TEST-1234",
            "first_observed_epoch": 1_700_000_000,
            "occurrence_count": 3,
        }
        environment = {
            "TZ": "America/New_York",
            "MAIL_RELAY_HOSTNAME": "relay [test]",
        }
        evidence = (
            "AADSTS900021 Trace ID: safe-trace Correlation ID: safe-correlation "
            "Bearer must-not-leak eyJabcdefghijklmnopqrstuv.abcdefghijk.abcdefghijk"
        )
        with mock.patch.dict(os.environ, environment, clear=False):
            payload = alert.build_payload(incident, "recovered", 1_700_000_125, evidence)
        self.assertEqual(payload["reference_id"], "PMR-TEST-1234")
        self.assertEqual(payload["duration_seconds"], 125)
        self.assertEqual(payload["timezone"], "America/New_York")
        self.assertNotEqual(payload["observed_utc"], payload["observed_local"])
        self.assertIn("safe-correlation", payload["evidence"])
        self.assertNotIn("must-not-leak", payload["evidence"])
        self.assertNotIn("eyJabcdefghijklmnopqrstuv", payload["evidence"])
        self.assertTrue(payload["likely_causes"])
        self.assertTrue(payload["remediation"])
        self.assertIn("RUNBOOK", payload["runbook_url"].upper())

    def test_open_is_restart_durable_duplicate_suppressed_and_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"MAIL_ALERT_STATE_DIR": directory, "TZ": "UTC"}
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(alert.time, "time", side_effect=[1000, 1000, 1010, 1010, 1060, 1060]), \
                    mock.patch.object(alert.secrets, "token_hex", return_value="a1b2c3d4"):
                for argv in (
                    ["alert-event.py", "open", "error", "token-health", "first failure"],
                    ["alert-event.py", "open", "error", "token-health", "second failure"],
                ):
                    with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(alert.main(), 0)
                incident_path = Path(directory) / "incidents" / "token-health.json"
                incident = json.loads(incident_path.read_text())
                self.assertEqual(incident["reference_id"], "PMR-19700101-A1B2C3D4")
                self.assertEqual(incident["occurrence_count"], 2)
                with mock.patch.object(
                    sys,
                    "argv",
                    ["alert-event.py", "recover", "token-health", "fresh token minted"],
                ), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(alert.main(), 0)
                self.assertFalse(incident_path.exists())

    def test_failed_email_does_not_suppress_webhook_and_remains_retryable(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = Path(directory) / "outbox.json"
            payload = {
                "reference_id": "PMR-TEST-CHANNELS",
                "status": "open",
                "severity": "error",
                "event": "relay-health",
            }
            alert.atomic_json(
                outbox,
                {"payload": payload, "email_pending": True, "webhook_pending": True},
            )
            with mock.patch.object(alert, "deliver_email", return_value=(False, "listener down")), \
                    mock.patch.object(alert, "deliver_webhook", return_value=(True, "HTTP success")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(alert.attempt_outbox(outbox))
            retained = json.loads(outbox.read_text())
            self.assertTrue(retained["email_pending"])
            self.assertFalse(retained["webhook_pending"])
            self.assertEqual(retained["email_attempts"], 1)
            self.assertGreater(retained["email_next_attempt_epoch"], alert.time.time())
            # A second health category in the same verifier run must not make
            # another connection attempt before the persisted backoff expires.
            with mock.patch.object(alert, "deliver_email") as email, \
                    mock.patch.object(alert, "deliver_webhook") as webhook, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(alert.attempt_outbox(outbox))
            email.assert_not_called()
            webhook.assert_not_called()


class ListKeysReportTests(unittest.TestCase):
    """The `--list-keys` report classifies Microsoft's real keyCredentials
    response into LIVE / RETIRING / ORPHAN and prints a removal hint per orphan.

    The fixture at tests/fixtures/keycredentials.json is a redacted capture from a
    live Entra tenant whose customKeyIdentifier encoding (uppercase hex, not the
    base64 the Graph docs describe) is capture-verified. Treating that encoding
    wrong once mislabelled the live certificate an orphan and invited its
    deletion, so the report is exercised against the real shape here.
    """

    FIXTURE = json.loads((ROOT / "tests/fixtures/keycredentials.json").read_text())

    def test_fixture_reflects_the_observed_graph_shape(self):
        credential = self.FIXTURE["value"][0]["keyCredentials"][0]
        for field in ("customKeyIdentifier", "displayName", "keyId",
                      "endDateTime", "type", "usage"):
            self.assertIn(field, credential)
        # Capture-verified: this tenant returns the SHA-1 thumbprint as 40 upper
        # hex characters, which credential_thumbprint must accept unchanged.
        identifier = credential["customKeyIdentifier"]
        self.assertEqual(len(identifier), 40)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in identifier))
        self.assertEqual(rotate.credential_thumbprint(credential), identifier)

    def _render_report(self, build_credentials, pending_removal=None):
        """Run `main(['--list-keys'])` against a stubbed Graph and return its
        report. A freshly generated OAuth key/cert supplies the live thumbprint;
        token minting and the Graph GET are replaced with recording fakes so the
        test never touches Microsoft."""
        from cryptography.hazmat.primitives import hashes, serialization
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets"  # Rotation refuses any path outside secrets/
            secrets.mkdir()
            key_path = secrets / "mail_relay_client_key.pem"
            cert_path = secrets / "mail_relay_client_cert.pem"
            key, cert = rotate.make_certificate(3650, 2048, "Mail Relay")
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            live_thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
            env = {
                "MAIL_RELAY_TENANT": "00000000-0000-0000-0000-000000000000",
                "MAIL_RELAY_CLIENT_ID": "11111111-1111-1111-1111-111111111111",
                "MAIL_SEND_MAILBOX": "relay@example.invalid",
                "MAIL_RELAY_KEY_FILE": str(key_path),
                "MAIL_RELAY_CERT_FILE": str(cert_path),
                "MAIL_ROTATION_STATE_FILE": str(root / "state.json"),
                "MAIL_ROTATION_LOG_FILE": str(root / "rotation.log"),
            }
            app = {"keyCredentials": build_credentials(live_thumbprint)}
            with mock.patch.dict(os.environ, env, clear=False), \
                    mock.patch.object(rotate.Rotation, "token", return_value="fake-token"), \
                    mock.patch.object(rotate.Rotation, "graph", return_value=(200, app)), \
                    mock.patch.object(rotate.Rotation, "read_state",
                                      return_value={"pending_removal": pending_removal or {}}), \
                    mock.patch.object(sys, "argv",
                                      ["rotate", "--list-keys", "--env-file", str(root / "absent.env")]):
                buffer = io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    code = rotate.main()
            return code, buffer.getvalue(), live_thumbprint

    def test_report_classifies_live_retiring_and_orphan(self):
        template = self.FIXTURE["value"][0]["keyCredentials"][0]
        live_id = "33333333-3333-3333-3333-333333333333"
        retiring_id = "44444444-4444-4444-4444-444444444444"
        orphan_id = "55555555-5555-5555-5555-555555555555"

        def build_credentials(live_thumbprint):
            # Live: customKeyIdentifier is the on-disk cert's thumbprint, in the
            # capture-verified uppercase-hex encoding Microsoft actually returns.
            live = dict(template, customKeyIdentifier=live_thumbprint, keyId=live_id)
            retiring = dict(template, customKeyIdentifier="0" * 40,
                            keyId=retiring_id, displayName="previous")
            orphan = dict(template, customKeyIdentifier="F" * 40,
                          keyId=orphan_id, displayName="abandoned")
            return [live, retiring, orphan]

        pending = {"key_id": retiring_id, "rotated_at": alert.time.time()}
        code, report, live_thumbprint = self._render_report(build_credentials, pending)

        self.assertEqual(code, 0)
        self.assertIn("3 key credential(s)", report)
        self.assertIn(live_thumbprint, report)
        self.assertIn("LIVE", report)
        self.assertIn("RETIRING", report)
        self.assertIn("ORPHAN", report)
        # Only the orphan earns a removal hint; the live and retiring keys never do.
        self.assertIn(f"--remove-key {orphan_id}", report)
        self.assertNotIn(f"--remove-key {retiring_id}", report)
        self.assertNotIn(f"--remove-key {live_id}", report)


class RemoveKeyAlreadyGoneTests(unittest.TestCase):
    """removeKey classification against a captured live 400. Microsoft answers a
    removal of an absent key with the GENERIC code "Request_BadRequest" plus the
    specific message "No credentials found to be removed."; graph() hands the
    body back as a raw string. The fixture is that real envelope (request ids
    zeroed). A different Request_BadRequest must NOT be read as already-gone, or a
    key that is still present would be abandoned mid-rotation."""

    BODY = (ROOT / "tests/fixtures/removekey-no-credentials-400.json").read_text().strip()

    def test_captured_400_string_is_already_gone(self):
        # graph() returns the error body as a string -- exercise that exact form.
        self.assertTrue(rotate.remove_key_already_gone(400, self.BODY))

    def test_same_envelope_as_dict_is_also_recognised(self):
        self.assertTrue(rotate.remove_key_already_gone(400, json.loads(self.BODY)))

    def test_other_bad_request_is_not_already_gone(self):
        # Same generic code, different meaning: must not masquerade as success.
        other = '{"error":{"code":"Request_BadRequest","message":"Invalid proof of possession token."}}'
        self.assertFalse(rotate.remove_key_already_gone(400, other))

    def test_real_invalid_cert_400_is_not_already_gone(self):
        # Captured live 2026-08-21: an invalid certificate addKey fails with the
        # SAME generic code "Request_BadRequest" as the absent-key removeKey, but
        # a different message. Proof that matching on code alone would misfire --
        # this real envelope must NOT be read as "already gone".
        invalid = (ROOT / "tests/fixtures/addkey-invalid-cert-400.json").read_text().strip()
        self.assertFalse(rotate.remove_key_already_gone(400, invalid))

    def test_non_400_status_is_never_already_gone(self):
        self.assertFalse(rotate.remove_key_already_gone(200, self.BODY))
        self.assertFalse(rotate.remove_key_already_gone(500, self.BODY))

    def test_non_json_body_preserves_substring_fallback(self):
        self.assertTrue(rotate.remove_key_already_gone(400, "No credentials found to be removed."))
        self.assertFalse(rotate.remove_key_already_gone(400, "some unrelated gateway error"))


class RotationWindowTests(unittest.TestCase):
    """The OAuth rotation window must keep the renewal threshold strictly inside
    the certificate's life, matching the inbound-TLS guard the entrypoint already
    enforces. renew_at >= validity churns; renew_at <= 0 rotates only after the
    certificate is already dead; a one-day certificate cannot satisfy either."""

    def test_safe_windows_are_accepted(self):
        self.assertEqual(rotate.rotation_window_error(730, 365), "")   # defaults
        self.assertEqual(rotate.rotation_window_error(2, 1), "")       # smallest viable
        self.assertEqual(rotate.rotation_window_error(3650, 1825), "")  # ten-year

    def test_threshold_at_or_beyond_validity_is_rejected(self):
        self.assertNotEqual(rotate.rotation_window_error(30, 365), "")  # renew after life
        self.assertNotEqual(rotate.rotation_window_error(10, 10), "")   # equal
        self.assertNotEqual(rotate.rotation_window_error(10, 11), "")

    def test_zero_or_negative_threshold_is_rejected(self):
        self.assertNotEqual(rotate.rotation_window_error(30, 0), "")
        self.assertNotEqual(rotate.rotation_window_error(30, -5), "")

    def test_one_day_certificate_is_rejected(self):
        # renew_at defaults to 1 // 2 == 0, which no window can rescue.
        self.assertNotEqual(rotate.rotation_window_error(1, 1 // 2), "")

    def test_sub_one_day_validity_is_rejected(self):
        self.assertNotEqual(rotate.rotation_window_error(0, 0), "")
        self.assertNotEqual(rotate.rotation_window_error(-3, -1), "")

    def test_guard_is_wired_into_the_network_rotation_path(self):
        # A misconfigured window must abort before any tenant contact. main()
        # reaches the guard after the offline --generate-only branch and before
        # reading the environment, so no network or credentials are needed.
        with mock.patch.object(sys, "argv",
                               ["rotate", "--validity", "30", "--renew-at", "365"]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                rotate.main()
        self.assertEqual(caught.exception.code, 2)  # argparse parser.error exit code


class AddKeyResponseTests(unittest.TestCase):
    """Captured live addKey 200 (2026-08-21). The rotation path reads
    result["keyId"] to record the pending addition
    (rotate-smtp-relay-cert.py: added_key_id = result["keyId"]). This fixture
    pins that shape and two capture-verified facts: the tenant ACCEPTS a
    3650-day certificate (no upper validity cap observed), and returns the
    customKeyIdentifier in uppercase hex."""

    RESPONSE = json.loads((ROOT / "tests/fixtures/addkey-response-200.json").read_text())

    def test_response_exposes_the_top_level_keyid_the_code_reads(self):
        # The exact extraction the rotation path performs must succeed.
        added_key_id = self.RESPONSE["keyId"]
        self.assertEqual(len(added_key_id), 36)
        self.assertEqual(added_key_id.count("-"), 4)

    def test_identifier_is_hex_and_ten_year_span_is_accepted(self):
        identifier = self.RESPONSE["customKeyIdentifier"]
        self.assertEqual(len(identifier), 40)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in identifier))
        start = self.RESPONSE["startDateTime"][:4]
        end = self.RESPONSE["endDateTime"][:4]
        self.assertGreaterEqual(int(end) - int(start), 10)  # ~10-year span accepted


if __name__ == "__main__":
    unittest.main(verbosity=2)
