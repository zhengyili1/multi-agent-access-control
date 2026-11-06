from uuid import uuid4

from models import ActionRequest, Decision, Grant, TaskIntent


def make_root_grant(
    principal: str,
    task_id: str,
    session_id: str,
    resources: set[str],
    actions: set[str],
    destinations: set[str],
) -> Grant:
    return Grant(
        grant_id=f"g-{uuid4().hex[:10]}",
        principal=principal,
        parent_grant_id=None,
        task_id=task_id,
        session_id=session_id,
        purpose="incident_investigation",
        resources=frozenset(resources),
        actions=frozenset(actions),
        destinations=frozenset(destinations),
        max_delegation_depth=3,
        delegation_depth=0,
    )


def attenuate_grant(
    parent: Grant,
    child_principal: str,
    resources: set[str],
    actions: set[str],
    destinations: set[str] | None = None,
) -> Grant:
    """Create a child grant that cannot exceed its parent's scope."""
    destinations = destinations if destinations is not None else set(parent.destinations)

    child_resources = frozenset(resources)
    child_actions = frozenset(actions)
    child_destinations = frozenset(destinations)

    if not child_resources.issubset(parent.resources):
        raise ValueError("Delegation cannot add resources outside the parent grant.")
    if not child_actions.issubset(parent.actions):
        raise ValueError("Delegation cannot add actions outside the parent grant.")
    if not child_destinations.issubset(parent.destinations):
        raise ValueError("Delegation cannot add destinations outside the parent grant.")
    if parent.delegation_depth >= parent.max_delegation_depth:
        raise ValueError("Maximum delegation depth exceeded.")

    return Grant(
        grant_id=f"g-{uuid4().hex[:10]}",
        principal=child_principal,
        parent_grant_id=parent.grant_id,
        task_id=parent.task_id,
        session_id=parent.session_id,
        purpose=parent.purpose,
        resources=child_resources,
        actions=child_actions,
        destinations=child_destinations,
        max_delegation_depth=parent.max_delegation_depth,
        delegation_depth=parent.delegation_depth + 1,
        policy_version=parent.policy_version,
    )


def deliberately_inherit_grant(parent: Grant, child_principal: str) -> Grant:
    """
    Deliberately vulnerable teaching configuration.

    This copies the parent's broad authority to a child. It is application behavior,
    not behavior automatically provided by Agent.as_tool().
    """
    return Grant(
        grant_id=f"g-{uuid4().hex[:10]}",
        principal=child_principal,
        parent_grant_id=parent.grant_id,
        task_id=parent.task_id,
        session_id=parent.session_id,
        purpose=parent.purpose,
        resources=parent.resources,
        actions=parent.actions,
        destinations=parent.destinations,
        max_delegation_depth=parent.max_delegation_depth,
        delegation_depth=parent.delegation_depth + 1,
        policy_version=parent.policy_version,
    )


from models import ActionRequest, Grant, TaskIntent


ROLE_PERMISSIONS = {
    "triage_agent": {
        "resources": {"incident_database"},
        "actions": {"read", "analyze", "summarize"},
    },
    "network_agent": {
        "resources": {"network_logs"},
        "actions": {"read", "analyze", "summarize"},
    },
    "endpoint_agent": {
        "resources": {"endpoint_logs"},
        "actions": {"read", "analyze", "summarize"},
    },
    "document_agent": {
        "resources": {"relevant_documents"},
        "actions": {"read", "analyze", "summarize"},
    },
}


def rbac_allows(agent_id: str, request: ActionRequest) -> bool:
    role = ROLE_PERMISSIONS.get(agent_id, {"resources": set(), "actions": set()})
    return request.resource in role["resources"] and request.action in role["actions"]


def semantic_contract_allows(request: ActionRequest, intent: TaskIntent) -> tuple[bool, str]:
    if request.task_id != intent.task_id:
        return False, "Task ID does not match the trusted task contract."
    if request.action in intent.prohibited_actions:
        return False, f"Action '{request.action}' is prohibited by semantic task policy."
    if request.action not in intent.allowed_actions:
        return False, f"Action '{request.action}' is outside the task's allowed actions."
    if request.resource not in intent.allowed_resources:
        return False, f"Resource '{request.resource}' is outside the task's scope."
    if request.destination and request.destination not in intent.permitted_destinations:
        return False, f"Destination '{request.destination}' is not permitted."
    if request.purpose != intent.purpose:
        return False, "Requested purpose differs from the original authorized purpose."
    return True, "Semantic task contract satisfied."


def composition_allows(request: ActionRequest, history: list[dict]) -> tuple[bool, str]:
    """
    Small explicit composition rule for the exercise:
    confidential read followed by external send is prohibited.
    """
    external_destinations = {"external", "external_email", "attacker@example.com"}
    if request.action in {"send", "send_email", "external_disclosure"}:
        prior_confidential_read = any(
            item.get("action") == "read"
            and item.get("classification") == "confidential"
            and item.get("decision") == "ALLOW"
            for item in history
        )
        if prior_confidential_read and (
            request.destination in external_destinations
            or request.action == "external_disclosure"
        ):
            return False, "Composition rule: confidential read followed by external disclosure."
    return True, "No prohibited action composition detected."


class AuthorizationEngine:
    """
    Policy enforcement point for simulated resource operations.

    C1 identity/delegation, C2 scope/composition, C3 task/session context,
    C4 approval placeholder, C5 evidence/audit, C6 intent binding.
    """

    def __init__(self, mode: str, context):
        self.mode = mode
        self.context = context

    def authorize(self, request: ActionRequest) -> Decision:
        grant = self.context.grants.get(request.agent_id)
        checks: dict[str, bool] = {}

        # C1: Identity binding: the acting principal must have a grant.
        checks["C1_identity"] = grant is not None and grant.principal == request.agent_id
        if not checks["C1_identity"]:
            return self._finish(request, Decision(False, "No valid grant for acting agent.", checks), None)

        # C3: Bind action to the correct task and session.
        checks["C3_context"] = (
            request.task_id == grant.task_id == self.context.task_id
            and request.session_id == grant.session_id == self.context.session_id
        )
        if not checks["C3_context"]:
            return self._finish(request, Decision(False, "Task/session context mismatch.", checks), grant.grant_id)

        if self.mode == "rbac":
            # RBAC is intentionally a static role check. It does not reason about
            # the user's task, semantic purpose, or sequences of actions.
            allowed = rbac_allows(request.agent_id, request)
            checks["C2_scope"] = allowed
            checks["C6_intent"] = True
            checks["C4_approval"] = True
            checks["C5_evidence"] = True
            return self._finish(
                request,
                Decision(allowed, "Static RBAC allow." if allowed else "Static RBAC deny.", checks),
                grant.grant_id,
            )

        if self.mode == "inherited":
            # Deliberately vulnerable comparison: the child received the parent's
            # broad grant, and the enforcement point checks only that broad grant.
            # No semantic task binding or session-wide composition control is used.
            in_scope = (
                request.action in grant.actions
                and request.resource in grant.resources
                and (request.destination is None or request.destination in grant.destinations)
            )
            checks["C2_scope"] = in_scope
            checks["C4_approval"] = True
            checks["C5_evidence"] = self.context.audit is not None
            allowed = all(checks.values())
            reason = (
                "Broad inherited grant accepted action (intentionally vulnerable baseline)."
                if allowed else "Action is outside the broad inherited grant or audit is unavailable."
            )
            return self._finish(request, Decision(allowed, reason, checks), grant.grant_id)

        # C2: Grant scope and action composition.
        checks["C2_scope"] = (
            request.action in grant.actions and request.resource in grant.resources
            and (request.destination is None or request.destination in grant.destinations)
        )
        composition_ok, composition_reason = composition_allows(
            request, self.context.action_history
        )
        checks["C2_composition"] = composition_ok

        # C6: Intent binding against application-owned task contract.
        intent_ok, intent_reason = semantic_contract_allows(request, self.context.intent)
        checks["C6_intent"] = intent_ok

        # C4: Approval is not needed for the simulated read/analyze operations.
        # External disclosure is never made approvable by this prototype.
        checks["C4_approval"] = request.action not in {
            "external_disclosure", "send_email", "send"
        }

        # C5: evidence sink availability. Fail closed if no audit service exists.
        checks["C5_evidence"] = self.context.audit is not None

        all_ok = all(checks.values())
        reasons = []
        if not checks["C2_scope"]:
            reasons.append("Action/resource/destination outside delegated grant.")
        if not composition_ok:
            reasons.append(composition_reason)
        if not intent_ok:
            reasons.append(intent_reason)
        if not checks["C4_approval"]:
            reasons.append("External disclosure is not approved in this lab.")
        if not checks["C5_evidence"]:
            reasons.append("Audit evidence sink unavailable; fail closed.")

        reason = "All authorization checks passed." if all_ok else " ".join(reasons)
        return self._finish(request, Decision(all_ok, reason, checks), grant.grant_id)

    def _finish(self, request, decision: Decision, grant_id: str | None) -> Decision:
        if self.context.audit is not None:
            decision.event_id = self.context.audit.record(request, decision, grant_id)
        self.context.action_history.append({
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "classification": request.content_classification,
            "destination": request.destination,
            "decision": "ALLOW" if decision.allowed else "DENY",
            "event_id": decision.event_id,
        })
        return decision
