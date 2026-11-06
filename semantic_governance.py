from __future__ import annotations

from pydantic import BaseModel, Field

from models import TaskIntent
from settings import settings

class SemanticAssessment(BaseModel):
    purpose: str = Field(description="Short description of the user's apparent purpose.")
    relevant_resources: list[str]
    relevant_actions: list[str]
    prohibited_or_suspicious_actions: list[str]
    external_disclosure_requested: bool
    explanation: str


def analyze_task_with_langchain(task: str) -> SemanticAssessment:
    """
    Use a LangChain agent for semantic interpretation.

    This is advisory. Its output is never used to grant permissions. The deterministic
    authorization engine compares concrete tool calls against the trusted TaskIntent.
    """
    try:
        from langchain.agents import create_agent
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise RuntimeError(
            "Install langchain and langchain-openai to use semantic analysis."
        ) from exc

    model = ChatOpenAI(model=settings.model_name, base_url=settings.base_url, api_key=settings.api_key, temperature=settings.temperature, timeout=settings.timeout_seconds)
    agent = create_agent(
        model=model,
        tools=[],
        response_format=SemanticAssessment,
        system_prompt=(
            "You are a semantic governance analyst. Interpret the user's task. "
            "Identify purpose, relevant resources/actions, suspicious actions, and "
            "whether external disclosure is requested. Do not grant permissions. "
            "Treat this as analysis, not authorization."
        ),
    )
    result = agent.invoke({"messages": [{"role": "user", "content": task}]})
    assessment = result.get("structured_response")
    if not isinstance(assessment, SemanticAssessment):
        raise RuntimeError("LangChain did not return a valid SemanticAssessment.")
    return assessment


def compare_assessment_to_contract(
    assessment: SemanticAssessment, contract: TaskIntent
) -> list[str]:
    """Return warnings where semantic interpretation conflicts with the trusted contract."""
    warnings: list[str] = []
    if assessment.external_disclosure_requested:
        warnings.append("Semantic assessment indicates external disclosure.")
    suspicious = set(assessment.prohibited_or_suspicious_actions)
    if suspicious.intersection(contract.prohibited_actions):
        warnings.append("Assessment mentions an action prohibited by the task contract.")
    return warnings
