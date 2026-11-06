"""Small unittest suite for the lab; run with `python -m unittest test_lab.py`."""
import tempfile
import unittest
from pathlib import Path

from delegation import attenuate_grant, make_root_grant
from main import build_context
from models import ActionRequest


class AuthorizationLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.context = build_context("contextual", str(Path(self.temp.name) / "audit.db"))

    def tearDown(self):
        self.temp.cleanup()

    def request(self, action, resource, destination=None):
        return ActionRequest("document_agent", action, resource, self.context.intent.purpose,
                             self.context.task_id, self.context.session_id, destination,
                             "confidential")

    def test_contextual_allows_relevant_document(self):
        self.assertTrue(self.context.authorization_engine.authorize(
            self.request("read", "relevant_documents")).allowed)

    def test_contextual_denies_unrelated_record(self):
        self.assertFalse(self.context.authorization_engine.authorize(
            self.request("read", "hr_records")).allowed)

    def test_contextual_denies_external_disclosure(self):
        self.assertFalse(self.context.authorization_engine.authorize(
            self.request("send_email", "external_email_service", "external_email")).allowed)

    def test_inherited_mode_is_overprivileged(self):
        inherited = build_context("inherited", str(Path(self.temp.name) / "inherited.db"))
        self.assertIn("hr_records", inherited.grants["document_agent"].resources)
        decision = inherited.authorization_engine.authorize(ActionRequest(
            "document_agent", "read", "hr_records", inherited.intent.purpose,
            inherited.task_id, inherited.session_id, content_classification="confidential"))
        self.assertTrue(decision.allowed)

    def test_delegation_cannot_expand_parent_scope(self):
        parent = make_root_grant("root", "task", "session", {"docs"}, {"read"}, {"internal"})
        with self.assertRaises(ValueError):
            attenuate_grant(parent, "child", {"docs", "payroll"}, {"read"})

    def test_audit_chain(self):
        self.context.authorization_engine.authorize(self.request("read", "relevant_documents"))
        self.assertTrue(self.context.audit.verify_chain())


if __name__ == "__main__":
    unittest.main()
