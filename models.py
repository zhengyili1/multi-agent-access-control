from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class TaskIntent:
    task_id: str
    purpose: str
    allowed_resources: frozenset[str]
    allowed_actions: frozenset[str]
    prohibited_actions: frozenset[str]
    permitted_destinations: frozenset[str]
    sensitivity: str = "confidential"


@dataclass(frozen=True)
class Grant:
    grant_id: str
    principal: str
    parent_grant_id: str | None
    task_id: str
    session_id: str
    purpose: str
    resources: frozenset[str]
    actions: frozenset[str]
    destinations: frozenset[str]
    max_delegation_depth: int = 2
    delegation_depth: int = 0
    policy_version: str = "v1"


@dataclass(frozen=True)
class ActionRequest:
    agent_id: str
    action: str
    resource: str
    purpose: str
    task_id: str
    session_id: str
    destination: str | None = None
    content_classification: str = "internal"
    content: str = ""
    recipient: str | None = None


@dataclass
class Decision:
    allowed: bool
    reason: str
    checks: dict[str, bool] = field(default_factory=dict)
    event_id: str | None = None


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    agent_id: str
    action: str
    resource: str
    purpose: str
    decision: str
    reason: str
    grant_id: str | None
    session_id: str
    previous_hash: str
    event_hash: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
