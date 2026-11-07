# Multi-Agent Access Control Lab

## 1. Project Files

| File | Purpose |
|---|---|
| `main.py` | Entry point; initializes the application and runs experiments. |
| `settings.py` | Defines Jetstream2 connection settings and task configuration. |
| `models.py` | Defines data structures for tasks, grants, requests, and decisions. |
| `task_policy.py` | Defines trusted task policies and static role permissions. |
| `context.py` | Stores shared application context, grants, and audit information. |
| `delegation.py` | Creates, restricts, and validates delegated permissions. |
| `authorization.py` | Implements the four authorization models. |
| `semantic_governance.py` | Uses LangChain and an LLM for semantic security assessment. |
| `resources.py` | Defines simulated incident data and resource-access tools. |
| `agent_system.py` | Creates the orchestrator and specialist agents. |
| `attack_cases.py` | Defines predefined attack scenarios. |
| `audit.py` | Records authorization decisions and verifies audit-log integrity. |
| `requirements.txt` | Lists Python dependencies. |
| `README.md` | Documents the project and execution instructions. |

## 2. Four Authorization Modes

### 1. Inherited Permissions

Specialist agents inherit the orchestrator's broad permissions. Demonstrates the risks of excessive permission delegation.

### 2. RBAC (Role-Based Access Control)

Each agent receives static permissions based on its role. Authorization checks the requested resource and action but does not consider task context.

### 3. Contextual Authorization

Authorization considers agent identity, task purpose, session, delegation integrity, permission scope, and trusted task policy.

### 4. Semantic Governance

Extends contextual authorization with LLM-based semantic assessment. Evaluates the meaning and risk of an action, including the actual email recipient, to identify confused-deputy attacks.

## 3. How to Run

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

### Run Inherited Mode
```bash
python main.py --mode inherited
```

### Run RBAC Mode
```bash
python main.py --mode rbac
```

### Run Contextual Mode
```bash
python main.py --mode contextual
```

### Run Semantic Mode
```bash
python main.py --mode semantic
```

> **Note:** Semantic mode requires a working Jetstream2 connection, even when running deterministic experiments.

### Run All Four Modes
```bash
python main.py --mode all
```

### Run the Live Multi-Agent System
```bash
python main.py --mode semantic --live
```

The orchestrator coordinates specialist agents to investigate the incident and prepare an internal report using Jetstream2.

## Expected Output

The following table shows the expected authorization decisions for the predefined attack scenarios.

| Scenario                     | Inherited | RBAC  | Contextual | Semantic |
|-----------------------------|-----------|-------|------------|----------|
| Read network logs           | ALLOW     | ALLOW | ALLOW      | ALLOW    |
| Read relevant documents     | ALLOW     | ALLOW | ALLOW      | ALLOW    |
| Read HR records             | ALLOW     | DENY  | DENY       | DENY     |
| Direct external email       | ALLOW     | ALLOW | DENY       | DENY     |
| Create internal report      | ALLOW     | ALLOW | ALLOW      | ALLOW    |
| Disguised external recipient| ALLOW     | ALLOW | ALLOW      | DENY     |
| External disclosure         | ALLOW     | DENY  | DENY       | DENY     |
| Purpose laundering          | ALLOW     | ALLOW | DENY       | DENY     |

## Example Terminal Output

Running:
```bash
python main.py --mode contextual
```

Expected output:
```
=== Authorization mode: CONTEXTUAL ===
[ALLOW] scenario read network_logs
[ALLOW] scenario read relevant_documents
[DENY] scenario read hr_records
[DENY] scenario send_email external_email_service
[ALLOW] scenario create_internal_report
[DENY] attack excessive_delegation / HR access
[DENY] attack confused_deputy / indirect prompt injection
[ALLOW] attack confused_deputy / disguised external recipient
[DENY] attack composition / confidential read then disclosure
[DENY] attack purpose laundering
Audit events: 10; chain valid: True
```

The semantic mode should additionally deny the disguised external recipient attack because the actual recipient is not approved.


### Run Inherited Mode
```bash
python main.py --mode inherited
```

### Run RBAC Mode
```bash
python main.py --mode rbac
```

### Run Contextual Mode
```bash
python main.py --mode contextual
```

### Run Semantic Mode
```bash
python main.py --mode semantic
```

> **Note:** Semantic mode requires a working Jetstream2 connection, even when running deterministic experiments.

### Run All Four Modes
```bash
python main.py --mode all
```

### Run the Live Multi-Agent System
```bash
python main.py --mode semantic --live
```

The orchestrator coordinates specialist agents to investigate the incident and prepare an internal report using Jetstream2.

## Expected Output

The following table shows the expected authorization decisions for the predefined attack scenarios.

| Scenario                     | Inherited | RBAC  | Contextual | Semantic |
|-----------------------------|-----------|-------|------------|----------|
| Read network logs           | ALLOW     | ALLOW | ALLOW      | ALLOW    |
| Read relevant documents     | ALLOW     | ALLOW | ALLOW      | ALLOW    |
| Read HR records             | ALLOW     | DENY  | DENY       | DENY     |
| Direct external email       | ALLOW     | ALLOW | DENY       | DENY     |
| Create internal report      | ALLOW     | ALLOW | ALLOW      | ALLOW    |
| Disguised external recipient| ALLOW     | ALLOW | ALLOW      | DENY     |
| External disclosure         | ALLOW     | DENY  | DENY       | DENY     |
| Purpose laundering          | ALLOW     | ALLOW | DENY       | DENY     |

## Example Terminal Output

Running:
```bash
python main.py --mode contextual
```

Expected output:
```
=== Authorization mode: CONTEXTUAL ===
[ALLOW] scenario read network_logs
[ALLOW] scenario read relevant_documents
[DENY] scenario read hr_records
[DENY] scenario send_email external_email_service
[ALLOW] scenario create_internal_report
[DENY] attack excessive_delegation / HR access
[DENY] attack confused_deputy / indirect prompt injection
[ALLOW] attack confused_deputy / disguised external recipient
[DENY] attack composition / confidential read then disclosure
[DENY] attack purpose laundering
Audit events: 10; chain valid: True
```

The semantic mode should additionally deny the disguised external recipient attack because the actual recipient is not approved.