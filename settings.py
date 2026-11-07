from dataclasses import dataclass
from enum import Enum
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Deterministic exercises can run before installing optional lab dependencies.
    pass


@dataclass(frozen=True)
class Settings:
    """Jetstream2 connection settings shared by both LLM integrations."""
    base_url: str = os.getenv("JETSTREAM_BASE_URL", "https://llm.jetstream-cloud.org/gpt-oss-120b/v1")
    api_key: str = os.getenv("JETSTREAM_API_KEY", "not-required")
    model_name: str = os.getenv("JETSTREAM_MODEL_NAME", "gpt-oss-120b")
    temperature: float = float(os.getenv("MODEL_TEMPERATURE", "0"))
    timeout_seconds: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


settings = Settings()


class AuthorizationMode(str, Enum):
    RBAC = "rbac"
    INHERITED = "inherited"
    CONTEXTUAL = "contextual"
    SEMANTIC = "semantic"


TASK_ID = "INC-2026-001"
SESSION_ID = "SESSION-INC-2026-001"
ORIGINAL_TASK = (
    "Investigate Alice's suspicious activity. Review relevant incident, network, "
    "endpoint, and supporting document evidence. Prepare an internal incident report. "
    "Do not disclose confidential information externally."
)
