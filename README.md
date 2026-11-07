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
