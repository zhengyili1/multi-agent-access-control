import argparse
import asyncio

from authorization import AuthorizationEngine
from attack_cases import attack_cases
from delegation import (
    attenuate_grant,
    deliberately_inherit_grant,
    make_root_grant,
)
from models import ActionRequest
from settings import AuthorizationMode, ORIGINAL_TASK, SESSION_ID, TASK_ID
from task_policy import trusted_incident_intent
from context import AppContext


# Each agent receives permissions based on its role.
ROLE_SCOPE = {
    "triage_agent": (
        {"incident_database"},
        {"read", "analyze", "summarize"},
    ),
    "network_agent": (
        {"network_logs"},
        {"read", "analyze", "summarize"},
    ),
    "endpoint_agent": (
        {"endpoint_logs"},
        {"read", "analyze", "summarize"},
    ),
    "document_agent": (
        {
            "relevant_documents",
            "internal_incident_report",
            "external_email_service",
        },
        {
            "read",
            "analyze",
            "summarize",
            "create_internal_report",
            "send_email",
        },
    ),
}


def build_context(mode: str) -> AppContext:
    """Create the task policy, grants, and authorization engine."""

    intent = trusted_incident_intent(TASK_ID)

    # The root grant is deliberately broad.
    # This allows the inherited mode to demonstrate excessive permissions.
    root = make_root_grant(
        "security_analyst",
        TASK_ID,
        SESSION_ID,
        {
            "incident_database",
            "network_logs",
            "endpoint_logs",
            "relevant_documents",
            "internal_incident_report",
            "external_email_service",
            "hr_records",
        },
        {
            "read",
            "analyze",
            "summarize",
            "create_internal_report",
            "send_email",
            "external_disclosure",
        },
        {
            "internal_report",
            "external_email",
        },
    )

    grants = {"orchestrator": root}

    for agent_id, (resources, actions) in ROLE_SCOPE.items():

        if mode == AuthorizationMode.INHERITED.value:
            # Vulnerable baseline: inherit the orchestrator's broad permissions.
            grants[agent_id] = deliberately_inherit_grant(root, agent_id)

        else:
            # Contextual and semantic modes also apply the trusted task policy.
            if mode in {
                AuthorizationMode.CONTEXTUAL.value,
                AuthorizationMode.SEMANTIC.value,
            }:
                resources = resources.intersection(intent.allowed_resources)
                actions = actions.intersection(intent.allowed_actions)

            destinations = {"internal_report"}

            if mode == AuthorizationMode.RBAC.value:
                resources = set(ROLE_SCOPE[agent_id][0])
                actions = set(ROLE_SCOPE[agent_id][1])

            grants[agent_id] = attenuate_grant(
                root,
                agent_id,
                set(resources),
                set(actions),
                destinations,
            )

    context = AppContext(
        mode=mode,
        task_id=TASK_ID,
        session_id=SESSION_ID,
        intent=intent,
        grants=grants,
    )

    context.authorization_engine = AuthorizationEngine(mode, context)

    return context


def run_deterministic(mode: str):
    """Run predefined requests and attack cases without real actions."""

    context = build_context(mode)

    print(f"\n=== Authorization mode: {mode.upper()} ===")

    requests = [
        ActionRequest(
            "network_agent",
            "read",
            "network_logs",
            context.intent.purpose,
            TASK_ID,
            SESSION_ID,
        ),

        ActionRequest(
            "document_agent",
            "read",
            "relevant_documents",
            context.intent.purpose,
            TASK_ID,
            SESSION_ID,
            content_classification="confidential",
            content="Incident note about Alice's suspicious host access.",
        ),

        ActionRequest(
            "document_agent",
            "read",
            "hr_records",
            context.intent.purpose,
            TASK_ID,
            SESSION_ID,
            content_classification="confidential",
            content="Employee Alice compensation record.",
        ),

        # Direct external disclosure.
        ActionRequest(
            "document_agent",
            "send_email",
            "external_email_service",
            context.intent.purpose,
            TASK_ID,
            SESSION_ID,
            "external_email",
            "confidential",
            "Incident report includes Alice's confidential investigation details.",
            "attacker@example.com",
        ),

        # Legitimate internal report creation.
        ActionRequest(
            "document_agent",
            "create_internal_report",
            "internal_incident_report",
            context.intent.purpose,
            TASK_ID,
            SESSION_ID,
            "internal_report",
            "confidential",
            "Alice's host accessed a sensitive internal service.",
        ),
    ]

    for req in requests:
        decision = context.authorization_engine.authorize(req)

        print(
            f"[{'ALLOW' if decision.allowed else 'DENY'}] "
            f"scenario {req.action} {req.resource}: {decision.reason}"
        )

    # Run the attack cases, including the disguised-recipient attack.
    for name, req in attack_cases(context):
        decision = context.authorization_engine.authorize(req)

        print(
            f"[{'ALLOW' if decision.allowed else 'DENY'}] "
            f"attack {name}: {decision.reason}"
        )


async def run_live(mode: str):
    """Run the multi-agent system using the Jetstream2-backed model."""

    from agents import Runner
    from agent_system import build_agents

    context = build_context(mode)

    result = await Runner.run(
        build_agents(mode)["orchestrator"],
        input=ORIGINAL_TASK,
        context=context,
        max_turns=20,
    )

    print("\n=== Orchestrator final report ===")
    print(result.final_output)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-agent access-control lab"
    )

    parser.add_argument(
        "--mode",
        choices=["inherited", "rbac", "contextual", "semantic", "all"],
        default="all",
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help="Run Jetstream2-backed Agents SDK agents.",
    )

    args = parser.parse_args()

    if args.live:
        if args.mode == "all":
            raise SystemExit(
                "Choose one mode for --live: "
                "inherited, rbac, contextual, or semantic."
            )

        asyncio.run(run_live(args.mode))

    else:
        modes = (
            ["inherited", "rbac", "contextual", "semantic"]
            if args.mode == "all"
            else [args.mode]
        )

        for mode in modes:
            run_deterministic(mode)


if __name__ == "__main__":
    main()

