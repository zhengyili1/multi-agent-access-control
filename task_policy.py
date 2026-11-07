from models import TaskIntent


# Static permissions used by the RBAC experiment.
# These permissions do not consider task purpose or email recipient.
ROLE_PERMISSIONS = {
    "triage_agent": {
        "resources": {"incident_database"},
        "actions": {"read", "analyze", "summarize"},
    },
    "network_agent": {
        "resources": {"network_logs"},
        "actions": {"read", "analyze", "summarize"},
    },
    "endpoint_agent": {
        "resources": {"endpoint_logs"},
        "actions": {"read", "analyze", "summarize"},
    },
    "document_agent": {
        "resources": {
            "relevant_documents",
            "internal_incident_report",
            "external_email_service",
        },
        "actions": {
            "read",
            "analyze",
            "summarize",
            "create_internal_report",
            "send_email",
        },
    },
}


def trusted_incident_intent(task_id: str) -> TaskIntent:
    """Define the trusted purpose and permitted operations for the investigation."""

    return TaskIntent(
        task_id=task_id,
        purpose="incident_investigation",
        allowed_resources=frozenset({
            "incident_database",
            "network_logs",
            "endpoint_logs",
            "relevant_documents",
            "internal_incident_report",
            "external_email_service",
        }),
        allowed_actions=frozenset({
            "read",
            "analyze",
            "summarize",
            "create_internal_report",
            "send_email",
        }),
        prohibited_actions=frozenset({
            "external_disclosure",
            "unauthorized_data_transfer",
            "delete",
            "modify_security_controls",
        }),
        permitted_destinations=frozenset({
            "internal_report",
        }),
        sensitivity="confidential",
    )