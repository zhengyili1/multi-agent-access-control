import argparse
import asyncio
from pathlib import Path

from audit import AuditLog
from authorization import AuthorizationEngine
from attacks import attack_cases
from delegation import attenuate_grant, deliberately_inherit_grant, make_root_grant
from models import ActionRequest
from settings import AuthorizationMode, ORIGINAL_TASK, SESSION_ID, TASK_ID
from task_policy import trusted_incident_intent
from context import AppContext

ROLE_SCOPE = {
    "triage_agent": ({"incident_database"}, {"read", "analyze", "summarize"}),
    "network_agent": ({"network_logs"}, {"read", "analyze", "summarize"}),
    "endpoint_agent": ({"endpoint_logs"}, {"read", "analyze", "summarize"}),
    "document_agent": ({"relevant_documents", "internal_incident_report"}, {"read", "analyze", "summarize", "create_internal_report"}),
}


def build_context(mode: str, db_path: str = "lab_audit.db") -> AppContext:
    intent = trusted_incident_intent(TASK_ID)
    audit = AuditLog(db_path)
    root = make_root_grant(
        "security_analyst", TASK_ID, SESSION_ID,
        {"incident_database", "network_logs", "endpoint_logs", "relevant_documents", "internal_incident_report", "external_email_service", "hr_records"},
        {"read", "analyze", "summarize", "create_internal_report", "send_email", "external_disclosure"},
        {"internal_report", "external_email"},
    )
    grants = {"orchestrator": root}
    for agent_id, (resources, actions) in ROLE_SCOPE.items():
        if mode == AuthorizationMode.INHERITED.value:
            grants[agent_id] = deliberately_inherit_grant(root, agent_id)
        else:
            if mode == AuthorizationMode.CONTEXTUAL.value:
                resources = resources.intersection(intent.allowed_resources)
                actions = actions.intersection(intent.allowed_actions)
            grants[agent_id] = attenuate_grant(root, agent_id, set(resources), set(actions), {"internal_report"})
    context = AppContext(mode=mode, task_id=TASK_ID, session_id=SESSION_ID, intent=intent, grants=grants, audit=audit)
    context.authorization_engine = AuthorizationEngine(mode, context)
    return context


def run_deterministic(mode: str):
    db = f"lab_{mode}.db"
    if Path(db).exists():
        Path(db).unlink()
    context = build_context(mode, db)
    print(f"\n=== Authorization mode: {mode.upper()} ===")
    for req in [
        ActionRequest("network_agent", "read", "network_logs", context.intent.purpose, TASK_ID, SESSION_ID),
        ActionRequest("document_agent", "read", "relevant_documents", context.intent.purpose, TASK_ID, SESSION_ID, content_classification="confidential"),
    ]:
        decision = context.authorization_engine.authorize(req)
        print(f"[{'ALLOW' if decision.allowed else 'DENY'}] legitimate {req.agent_id} -> {req.resource}: {decision.reason}")
    for name, req in attack_cases(context):
        decision = context.authorization_engine.authorize(req)
        print(f"[{'ALLOW' if decision.allowed else 'DENY'}] attack {name}: {decision.reason}")
    print(f"Audit events: {len(context.audit.rows())}; chain valid: {context.audit.verify_chain()}")
    return context


async def run_live(mode: str, semantic: bool):
    from agents import Runner
    from agent_system import build_agents
    context = build_context(mode, f"lab_live_{mode}.db")
    if semantic:
        from semantic_governance import analyze_task_with_langchain, compare_assessment_to_contract
        assessment = analyze_task_with_langchain(ORIGINAL_TASK)
        print("\nLangChain semantic assessment:")
        print(assessment.model_dump_json(indent=2))
        print("Contract warnings:", compare_assessment_to_contract(assessment, context.intent))
    result = await Runner.run(build_agents(mode)["orchestrator"], input=ORIGINAL_TASK, context=context, max_turns=20)
    print("\n=== Orchestrator final report ===")
    print(result.final_output)
    print(f"\nAudit events: {len(context.audit.rows())}; chain valid: {context.audit.verify_chain()}")


def main():
    parser = argparse.ArgumentParser(description="Multi-agent access-control lab")
    parser.add_argument("--mode", choices=["rbac", "inherited", "contextual", "all"], default="all")
    parser.add_argument("--live", action="store_true", help="Run Jetstream2-backed Agents SDK agents.")
    parser.add_argument("--semantic", action="store_true", help="Run LangChain semantic analysis (requires --live).")
    args = parser.parse_args()
    if args.live:
        if args.mode == "all":
            raise SystemExit("Choose one mode for --live: rbac, inherited, or contextual.")
        asyncio.run(run_live(args.mode, args.semantic))
    else:
        if args.semantic:
            raise SystemExit("--semantic requires --live.")
        for mode in (["rbac", "inherited", "contextual"] if args.mode == "all" else [args.mode]):
            run_deterministic(mode)


if __name__ == "__main__":
    main()
