from models import Decision
from delegation import validate_delegation_chain
from semantic_governance import semantic_governance_allows
from task_policy import ROLE_PERMISSIONS


class AuthorizationEngine:
    """Compare RBAC, inherited, contextual, and semantic authorization."""

    def __init__(self, mode, context):
        """Initialize the engine with an authorization mode and context."""
        self.mode = getattr(mode, "value", mode)
        self.context = context

    def authorize(self, request):
        """Check the agent's identity, task context, and requested permissions."""

        grant = self.context.grants.get(request.agent_id)

        if grant is None or grant.principal != request.agent_id:
            return self._finish(request, False, "Invalid agent identity.")

        if (
            request.task_id != grant.task_id
            or request.session_id != grant.session_id
            or request.task_id != self.context.task_id
            or request.session_id != self.context.session_id
        ):
            return self._finish(request, False, "Task/session mismatch.")

        # RBAC: check static role permissions.
        if self.mode == "rbac":
            role = ROLE_PERMISSIONS.get(request.agent_id, {})
            allowed = (
                request.resource in role.get("resources", set())
                and request.action in role.get("actions", set())
            )
            return self._finish(request, allowed, "RBAC decision.")

        # Inherited: check the broad delegated permissions.
        if self.mode == "inherited":
            allowed = self._scope(request, grant)
            return self._finish(
                request, allowed, "Inherited permission decision."
            )

        # Contextual and semantic authorization.
        if self.mode in {"contextual", "semantic"}:
            chain_ok, reason = validate_delegation_chain(
                grant, self.context.grants
            )
            if not chain_ok:
                return self._finish(request, False, reason)

            if not self._scope(request, grant):
                return self._finish(
                    request, False, "Delegated permission denied."
                )

            policy_ok, reason = self._check_task_policy(request)
            if not policy_ok:
                return self._finish(request, False, reason)

            if self.mode == "contextual":
                return self._finish(
                    request, True, "Contextual authorization passed."
                )

            if self.mode == "semantic":
                allowed, reason = semantic_governance_allows(
                    request, self.context.intent
                )
                return self._finish(request, allowed, reason)

        return self._finish(
            request, False, f"Unknown authorization mode: {self.mode}"
        )

    def _scope(self, request, grant):
        """Check the grant's action, resource, and destination scope."""
        return (
            request.action in grant.actions
            and request.resource in grant.resources
            and (
                request.destination is None
                or request.destination in grant.destinations
            )
        )

    def _check_task_policy(self, request):
        """Check the request against the trusted task contract."""
        intent = self.context.intent

        if request.purpose != intent.purpose:
            return False, "Task purpose mismatch."

        if request.action not in intent.allowed_actions:
            return False, "Action is not allowed by the task policy."

        if request.resource not in intent.allowed_resources:
            return False, "Resource is not allowed by the task policy."

        if request.action in intent.prohibited_actions:
            return False, "Action is explicitly prohibited."

        if (
            request.destination is not None
            and request.destination not in intent.permitted_destinations
        ):
            return False, "Destination is not permitted by the task policy."

        return True, "Task policy passed."

    def _finish(self, request, allowed, reason):
        """Store the decision in memory and return it."""
        decision = Decision(allowed=allowed, reason=reason)

        self.context.action_history.append({
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "classification": request.content_classification,
            "destination": request.destination,
            "task_id": request.task_id,
            "session_id": request.session_id,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
        })

        return decision

