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
    Controls whether an agent can access a resource or perform an action.

    Three authorization modes:
    - RBAC: Check static role permissions.
    - Inherited: Check permissions inherited from the parent agent.
    - Contextual: Check permissions, task context, action history,
      sensitive actions, and original task intent.

    Based on six APC conditions:
    C1: Identity
    C2: Scope and composition
    C3: Task and session context
    C4: Sensitive action restrictions
    C5: Audit evidence
    C6: Task intent
    """

    def __init__(self, mode, context):
        self.mode = mode
        self.context = context

    def authorize(self, request):
        """Check whether an agent's requested action is allowed."""

        # C1: Verify agent identity.
        grant = self.context.grants.get(request.agent_id)

        if grant is None or grant.principal != request.agent_id:
            return self._finish(request, False, "Invalid agent.")

        # C3: Verify task and session.
        if not self._check_context(request, grant):
            return self._finish(request, False, "Context mismatch.")

        # RBAC: Check static role permissions.
        if self.mode == "rbac":
            allowed = rbac_allows(request.agent_id, request)
            return self._finish(request, allowed, "RBAC decision.", grant.grant_id)

        # Inherited: Check the parent's delegated permissions.
        if self.mode == "inherited":
            allowed = self._check_scope(request, grant)
            return self._finish(
                request, allowed, "Inherited permission decision.", grant.grant_id
            )

        # Contextual: Evaluate APC conditions.
        checks = {
            "scope": self._check_scope(request, grant),
            "composition": self._check_composition(request),
            "safety": self._check_safety(request),
            "intent": self._check_intent(request),
            "audit": self.context.audit is not None,
        }

        allowed = all(checks.values())

        failed = [name for name, passed in checks.items() if not passed]
        reason = "All checks passed." if allowed else "Failed: " + ", ".join(failed)

        return self._finish(request, allowed, reason, grant.grant_id)

    def _check_context(self, request, grant):
        """C3: Check that the action belongs to the correct task and session."""
        return (
            request.task_id == grant.task_id == self.context.task_id
            and request.session_id == grant.session_id == self.context.session_id
        )

    def _check_scope(self, request, grant):
        """C2: Check that the action and resource are within delegated permissions."""
        return (
            request.action in grant.actions
            and request.resource in grant.resources
            and (
                request.destination is None
                or request.destination in grant.destinations
            )
        )

    def _check_composition(self, request):
        """C2: Check whether previous actions make this action unsafe."""
        allowed, _ = composition_allows(
            request, self.context.action_history
        )
        return allowed

    def _check_safety(self, request):
        """C4: Prohibit sensitive external disclosure operations."""
        return request.action not in {
            "send_email", "external_disclosure", "send"
        }

    def _check_intent(self, request):
        """C6: Check whether the action matches the original task."""
        allowed, _ = semantic_contract_allows(
            request, self.context.intent
        )
        return allowed

    def _finish(self, request, allowed, reason, grant_id=None):
        """C5: Record the authorization decision and update action history."""
        decision = Decision(allowed, reason, {})

        if self.context.audit is not None:
            decision.event_id = self.context.audit.record(
                request, decision, grant_id
            )

        self.context.action_history.append({
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "decision": "ALLOW" if allowed else "DENY",
            "event_id": decision.event_id,
        })

        return decision

