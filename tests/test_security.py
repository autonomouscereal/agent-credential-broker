import os
import json
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
        payload = {
            "password": "plain",
            "lease_token": "agent-bearer-token",
            "nested": {"api_key": "key", "safe": "value"},
            "items": [{"token": "abc"}],
        }
        self.assertEqual(broker.redact(payload)["password"], "<redacted>")
        self.assertEqual(broker.redact(payload)["lease_token"], "agent-bearer-token")
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
        with mock.patch.object(broker, "load_secret_for_claims", return_value="demo-secret-value"):
            with mock.patch.object(broker, "audit", return_value=None):
                response = broker.demo_provider_read({"lease_token": token, "query": "status"})
        text = json.dumps(response, sort_keys=True)
        self.assertNotIn("demo-secret-value", text)
        self.assertTrue(response["ok"])
        self.assertTrue(response["data"]["credential_injected"])
        self.assertFalse(response["secret_values_returned"])


if __name__ == "__main__":
    unittest.main()
