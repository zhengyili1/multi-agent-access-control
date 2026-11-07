from dataclasses import dataclass, field
from typing import Any

from models import Grant, TaskIntent


@dataclass
class AppContext:
    """Local application state shared with tools; not automatically shown to the LLM."""
    mode: str
    task_id: str
    session_id: str
    intent: TaskIntent
    grants: dict[str, Grant] = field(default_factory=dict)
    action_history: list[dict[str, Any]] = field(default_factory=list)
    audit: Any = None
    authorization_engine: Any = None
    semantic_assessor: Any = None
