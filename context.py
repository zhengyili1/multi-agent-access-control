from dataclasses import dataclass, field

from models import Grant, TaskIntent


@dataclass
class AppContext:
    """Shared application context for agents and authorization."""

    mode: str
    task_id: str
    session_id: str
    intent: TaskIntent
    grants: dict[str, Grant]
    action_history: list = field(default_factory=list)
    authorization_engine: object = None
    semantic_assessor: object = None
