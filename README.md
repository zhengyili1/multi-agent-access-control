# Multi-Agent Access Control Lab

A runnable teaching lab on multi-agent access control, contextual authorization, semantic governance, delegation, and confused-deputy attacks. It uses simulated local resources and supports two LLM integrations against the Jetstream2 OpenAI-compatible endpoint: the OpenAI Agents SDK and LangChain.

## Requirements

- Ubuntu 22.04/24.04 VM (one per student is recommended)
- Python 3.11 or newer
- Network access to the Jetstream2 LLM endpoint
- No GPU and no Docker required

## Set up the VM

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
# Clone/download the course lab, then enter its directory
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` only if the instructor provides different endpoint settings. The default values target Jetstream2's `gpt-oss-120b` endpoint. Keep credentials out of source control.

## Run the deterministic exercises

These do not call the LLM:

```bash
python main.py --mode all
python main.py --mode contextual
```

## Run with Jetstream2

```bash
python main.py --mode contextual --live
python main.py --mode contextual --live --semantic
```

Both the Agents SDK and LangChain use `JETSTREAM_BASE_URL`, `JETSTREAM_API_KEY`, and `JETSTREAM_MODEL_NAME` from `.env`. The Agents SDK connects through `OpenAIChatCompletionsModel` and `AsyncOpenAI`; LangChain uses `ChatOpenAI` with the same endpoint credentials. No OpenAI account key is needed when the provided Jetstream endpoint does not require one.

The `--semantic` option asks LangChain to interpret task intent. Its result is advisory and does not grant authority. Authorization remains bound to the application-owned policy contract and enforced at each resource tool.

## Modes and learning goals

- `rbac`: static role/resource permissions.
- `inherited`: deliberately vulnerable broad parent-grant copying, illustrating a confused deputy. This is application behavior, not automatic `Agent.as_tool()` permission inheritance.
- `contextual`: task, session, purpose, resource, action, delegation, and composition checks.

The attack cases cover excessive delegation, instructions embedded in untrusted documents, and prohibited action composition. Email sending and all datasets are simulated; no external message is sent.

## Project structure

```text
main.py
settings.py
models.py
task_policy.py
agent_system.py
delegation.py
authorization.py
semantic_governance.py
resources.py
attacks.py
audit.py
context.py
test_lab.py
requirements.txt
.env.example
.gitignore
README.md
```

## Exercises

1. Add a specialist with a narrowly scoped role.
2. Add a trusted task contract and attenuated child grant.
3. Add a composition policy for a sequence of actions.
4. Add approval requirements for high impact operations.
5. Add policy version checks and explain how stale grants are rejected.
6. Compare the three modes for utility, denial behavior, and audit evidence.

This prototype is designed for instruction, not production authorization.
