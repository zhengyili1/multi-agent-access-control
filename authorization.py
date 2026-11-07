from models import Decision
from delegation import validate_delegation_chain
from semantic_governance import semantic_governance_allows
from task_policy import ROLE_PERMISSIONS


class AuthorizationEngine:
    """Compare RBAC, inherited, contextual, and semantic authorization."""

    def __init__(self, mode, context):
        """Initialize the engine with an authorization mode and application context."""
        self.mode = getattr(mode, "value", mode)
        self.context = context

    def authorize(self, request):
        """Check an agent's identity, task context, and requested permissions."""

        grant = self.context.grants.get(request.agent_id)

        # Verify agent identity.
        if grant is None or grant.principal != request.agent_id:
            return self._finish(request, False, "Invalid agent identity.")

        # Verify task and session context.
        if (
            request.task_id != grant.task_id
            or request.session_id != grant.session_id
            or request.task_id != self.context.task_id
            or request.session_id != self.context.session_id
        ):
            return self._finish(request, False, "Task/session mismatch.")

        # -------------------------------------------------
        # RBAC: static role permissions
        # -------------------------------------------------
        if self.mode == "rbac":
            role = ROLE_PERMISSIONS.get(request.agent_id, {})

            allowed = (
                request.resource in role.get("resources", set())
                and request.action in role.get("actions", set())
            )

            return self._finish(request, allowed, "RBAC decision.")

        # -------------------------------------------------
        # Inherited: broad delegated permissions
        # -------------------------------------------------
        if self.mode == "inherited":
            allowed = self._scope(request, grant)

            return self._finish(
                request, allowed, "Inherited permission decision."
            )

        # -------------------------------------------------
        # Contextual and semantic authorization
        # -------------------------------------------------
        if self.mode in {"contextual", "semantic"}:

            # Verify delegation integrity.
            chain_ok, reason = validate_delegation_chain(
                grant, self.context.grants
            )

            if not chain_ok:
                return self._finish(request, False, reason)

            # Check delegated permissions.
            if not self._scope(request, grant):
                return self._finish(
                    request, False, "Delegated permission denied."
                )

            # Check the trusted task policy.
            policy_ok, reason = self._check_task_policy(request)

            if not policy_ok:
                return self._finish(request, False, reason)

            # Contextual mode uses task context and delegated permissions.
            if self.mode == "contextual":
                return self._finish(
                    request, True, "Contextual authorization passed."
                )

            # Semantic mode additionally evaluates the action using LangChain.
            if self.mode == "semantic":
                allowed, reason = semantic_governance_allows(
                    request, self.context.intent
                )

                return self._finish(request, allowed, reason)

        return self._finish(
            request, False, f"Unknown authorization mode: {self.mode}"
        )

    def _scope(self, request, grant):
        """Check whether the grant includes the requested action, resource, and destination."""

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
        """Record the authorization decision in the audit log and action history."""

        decision = Decision(
            allowed=allowed,
            reason=reason,
        )

        grant = self.context.grants.get(request.agent_id)

        if self.context.audit is not None:
            decision.event_id = self.context.audit.record(
                request,
                decision,
                grant.grant_id if grant else None,
            )

        self.context.action_history.append({
            "agent_id": request.agent_id,
            "action": request.action,
            "resource": request.resource,
            "classification": request.content_classification,
            "destination": request.destination,
            "task_id": request.task_id,
            "session_id": request.session_id,
            "decision": "ALLOW" if allowed else "DENY",
            "event_id": decision.event_id,
        })

        return decision

