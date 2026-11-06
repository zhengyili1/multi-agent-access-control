from uuid import uuid4

from models import Grant


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
