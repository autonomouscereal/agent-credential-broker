import os
import json
import secrets
import time
import unittest
from unittest import mock

from cryptography.fernet import Fernet

from src import broker


class CredentialBrokerSecurityTests(unittest.TestCase):
    def setUp(self):
        os.environ["BROKER_MASTER_KEY"] = Fernet.generate_key().decode("utf-8")

    def test_scope_matching_is_resource_and_action_specific(self):
        lease = {
            "system": "gitlab",
            "resource_type": "project",
            "resource_id": "team-a/*",
            "action": "read",
        }
        self.assertTrue(broker.scope_matches(lease, "gitlab", "project", "team-a/app", "read"))
        self.assertFalse(broker.scope_matches(lease, "gitlab", "project", "team-b/app", "read"))
        self.assertFalse(broker.scope_matches(lease, "gitlab", "project", "team-a/app", "write"))

    def test_lease_token_expires_and_contains_no_secret(self):
        lease = {
            "id": 7,
            "agent_id": "agent-1",
            "system": "demo",
            "resource_type": "dataset",
            "resource_id": "alpha",
            "action": "read",
            "expires_at": broker.utcnow() + broker.timedelta(seconds=60),
        }
        token = broker.issue_lease_token(lease, ttl_seconds=1)
        self.assertNotIn("secret", token.lower())
        claims = broker.verify_lease_token(token)
        self.assertEqual(claims["agent_id"], "agent-1")
        time.sleep(1.1)
        with self.assertRaises(PermissionError):
            broker.verify_lease_token(token)

    def test_redaction_removes_secret_fields(self):
        password_value = secrets.token_urlsafe(18)
        lease_token = secrets.token_urlsafe(18)
        recovery_code = secrets.token_urlsafe(18)
        api_key = secrets.token_urlsafe(18)
        nested_token = secrets.token_urlsafe(18)
        payload = {
            "password": password_value,
            "lease_token": lease_token,
            "submitted_values": {"recovery_code": recovery_code},
            "secret_values_returned": False,
            "credential_injected": True,
            "nested": {"api_key": api_key, "safe": "value"},
            "items": [{"token": nested_token}],
        }
        self.assertEqual(broker.redact(payload)["password"], "<redacted>")
        self.assertEqual(broker.redact(payload)["lease_token"], lease_token)
        self.assertEqual(broker.redact(payload)["submitted_values"], "<redacted>")
        self.assertFalse(broker.redact(payload)["secret_values_returned"])
        self.assertTrue(broker.redact(payload)["credential_injected"])
        self.assertEqual(broker.redact(payload)["nested"]["api_key"], "<redacted>")
        self.assertEqual(broker.redact(payload)["nested"]["safe"], "value")

    def test_demo_response_shape_has_no_secret_values(self):
        lease = {
            "id": 9,
            "agent_id": "agent-1",
            "system": "demo",
            "resource_type": "dataset",
            "resource_id": "alpha",
            "action": "read",
            "expires_at": broker.utcnow() + broker.timedelta(seconds=60),
        }
        token = broker.issue_lease_token(lease, ttl_seconds=60)
        provider_secret = secrets.token_urlsafe(32)
        with mock.patch.object(broker, "load_secret_for_claims", return_value=provider_secret):
            with mock.patch.object(broker, "audit", return_value=None):
                response = broker.demo_provider_read({"lease_token": token, "query": "status"})
        text = json.dumps(response, sort_keys=True)
        self.assertNotIn(provider_secret, text)
        self.assertTrue(response["ok"])
        self.assertTrue(response["data"]["credential_injected"])
        self.assertFalse(response["secret_values_returned"])

    def test_sensitive_intake_field_validation_is_strict(self):
        fields = broker.normalize_intake_fields([
            {"key": "account.password", "label": "Temporary password", "type": "password"},
            {"key": "mfa_code", "label": "MFA code", "type": "text", "required": False},
        ])
        self.assertEqual(fields[0]["key"], "account.password")
        self.assertTrue(fields[0]["required"])
        self.assertFalse(fields[1]["required"])
        with self.assertRaises(ValueError):
            broker.normalize_intake_fields([{"key": "bad key", "label": "Bad"}])
        with self.assertRaises(ValueError):
            broker.normalize_intake_fields([
                {"key": "password", "label": "One"},
                {"key": "password", "label": "Two"},
            ])

    def test_sensitive_intake_status_returns_refs_not_values(self):
        request = {
            "request_ref": "intake_abc",
            "agent_id": "agent-1",
            "purpose": "Need user-provided credential to finish ticket 42.",
            "status": "submitted",
            "fields": [
                {"key": "temporary_password", "label": "Temporary password", "type": "password", "required": True},
            ],
            "expires_at": broker.utcnow() + broker.timedelta(seconds=60),
            "submitted_at": broker.utcnow(),
        }
        values = [{
            "field_key": "temporary_password",
            "label": "Temporary password",
            "value_ref": "intake_abc:temporary_password",
            "encrypted_value": "encrypted-not-raw",
        }]
        response = broker.intake_status_payload(request, values)
        text = json.dumps(response, default=str, sort_keys=True)
        self.assertIn("intake_abc:temporary_password", text)
        self.assertFalse(response["secret_values_returned"])
        self.assertTrue(response["fields"][0]["submitted"])

    def test_demo_intake_provider_uses_values_without_returning_them(self):
        lease = {
            "id": 11,
            "agent_id": "agent-1",
            "system": "demo",
            "resource_type": "intake",
            "resource_id": "intake_abc",
            "action": "use",
            "expires_at": broker.utcnow() + broker.timedelta(seconds=60),
        }
        token = broker.issue_lease_token(lease, ttl_seconds=60)
        raw_values = {
            "temporary_password": secrets.token_urlsafe(32),
            "mfa_code": str(secrets.randbelow(900000) + 100000),
        }
        with mock.patch.object(broker, "resolve_intake_values", return_value=raw_values):
            with mock.patch.object(broker, "audit", return_value=None):
                response = broker.demo_provider_use_intake({"lease_token": token, "intake_ref": "intake_abc"})
        text = json.dumps(response, sort_keys=True)
        self.assertTrue(response["ok"])
        self.assertIn("temporary_password", response["fields_received"])
        for raw in raw_values.values():
            self.assertNotIn(raw, text)
        self.assertFalse(response["secret_values_returned"])


if __name__ == "__main__":
    unittest.main()
