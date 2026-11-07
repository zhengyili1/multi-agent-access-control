"""Run with `python3 -m unittest test_lab.py`."""
import tempfile
import unittest
from pathlib import Path

from delegation import attenuate_grant, make_root_grant
from main import build_context
from models import ActionRequest


class AuthorizationLabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def context(self, mode):
        return build_context(mode, str(Path(self.temp.name) / f"{mode}.db"))

    def req(self, ctx, action, resource, destination=None, purpose=None, content=""):
        return ActionRequest("document_agent", action, resource, purpose or ctx.intent.purpose,
                             ctx.task_id, ctx.session_id, destination, "confidential", content)

    def test_inherited_grant_allows_deputy_attack(self):
        ctx = self.context("inherited")
        decision = ctx.authorization_engine.authorize(self.req(
            ctx, "send_email", "external_email_service", "external_email",
            content="Confidential employee incident details"))
        self.assertTrue(decision.allowed)

    def test_rbac_denies_external_send(self):
        ctx = self.context("rbac")
        self.assertFalse(ctx.authorization_engine.authorize(self.req(
            ctx, "send_email", "external_email_service", "external_email")).allowed)

    def test_contextual_allows_relevant_read_and_denies_hr(self):
        ctx = self.context("contextual")
        self.assertTrue(ctx.authorization_engine.authorize(self.req(ctx, "read", "relevant_documents")).allowed)
        self.assertFalse(ctx.authorization_engine.authorize(self.req(ctx, "read", "hr_records")).allowed)

    def test_contextual_blocks_external_send(self):
        ctx = self.context("contextual")
        self.assertFalse(ctx.authorization_engine.authorize(self.req(
            ctx, "send_email", "external_email_service", "external_email")).allowed)

    def test_semantic_blocks_sensitive_external_content(self):
        ctx = self.context("semantic")
        decision = ctx.authorization_engine.authorize(self.req(
            ctx, "send_email", "external_email_service", "external_email",
            content="Alice employee confidential investigation report"))
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.checks["semantic_risk"])

    def test_semantic_blocks_purpose_laundering(self):
        ctx = self.context("semantic")
        self.assertFalse(ctx.authorization_engine.authorize(self.req(
            ctx, "read", "relevant_documents", purpose="employee_profiling")).allowed)

    def test_delegation_cannot_expand_parent_scope(self):
        parent = make_root_grant("root", "task", "session", {"docs"}, {"read"}, {"internal"})
        with self.assertRaises(ValueError):
            attenuate_grant(parent, "child", {"docs", "payroll"}, {"read"})

    def test_audit_hash_chain(self):
        ctx = self.context("contextual")
        ctx.authorization_engine.authorize(self.req(ctx, "read", "relevant_documents"))
        self.assertTrue(ctx.audit.verify_chain())


if __name__ == "__main__":
    unittest.main()
