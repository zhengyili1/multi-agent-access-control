# Multi-Agent Access Control Lab

A teaching lab on multi-agent access control, contextual authorization, semantic governance, delegation, and confused-deputy attacks. The live workflow uses OpenAI Agents SDK specialists exposed to the orchestrator with `Agent.as_tool()`, plus LangChain semantic assessment. Both use the Jetstream2 OpenAI-compatible endpoint.

## Requirements and VM setup

Use a Linux VM with Python 3.11+, network access to Jetstream2, and no GPU. Docker is not required.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
# clone the course repository and enter its directory
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

The default `.env.example` values use Jetstream2's `gpt-oss-120b` endpoint. Change them only if your instructor supplies different settings. Keep any credentials out of source control.

## Four experiments

Run reproducible policy scenarios without an LLM:

```bash
python3 main.py --mode all
```

Or run one level:

```bash
python3 main.py --mode inherited
python3 main.py --mode rbac
python3 main.py --mode contextual
python3 main.py --mode semantic
```

- **Inherited:** Vulnerable baseline. Copies the orchestrator's broad resources, actions, and destinations to specialists. Demonstrates excessive delegation and confused-deputy behavior.
- **RBAC:** Uses static agent role/resource/action permissions. Demonstrates the limits and value of role checks without task purpose or data-flow context.
- **Contextual:** Attenuates grants and checks task, session, purpose, destination, delegation chain, and action sequence. It blocks out-of-task access and external disclosure.
- **Semantic:** Includes all contextual checks and adds a deterministic content/purpose risk assessment for offline repeatability. It checks classification, employee-identifying content, purpose mismatch, and external destinations.

The deterministic scenarios include legitimate reads/report creation, unrelated HR access, prompt-injection-driven external sending, confidential-read-then-disclose composition, and purpose laundering. No email is sent; all data is simulated. Each decision is added to a local SQLite audit chain.

## Jetstream2 live experiments

Run the Agents SDK workflow, where the orchestrator calls specialist agents as tools:

```bash
python3 main.py --mode contextual --live
```

Run semantic mode with LangChain assessment at the task and each authorization boundary:

```bash
python3 main.py --mode semantic --live
```

Both integrations use `JETSTREAM_BASE_URL`, `JETSTREAM_API_KEY`, `JETSTREAM_MODEL_NAME`, `MODEL_TEMPERATURE`, and `LLM_TIMEOUT_SECONDS`. The Agents SDK uses `OpenAIChatCompletionsModel` with `AsyncOpenAI`; LangChain uses `ChatOpenAI` with the same endpoint settings. The semantic assessment can deny a high-risk request, but it cannot add permissions. Deterministic contextual checks remain mandatory. The default offline `--mode semantic` experiment uses a deterministic rule assessor so students can compare outcomes without an LLM call.

For quick local checks:

```bash
python3 -m unittest test_lab.py
```

## Defense methods students can inspect or extend

- **Least privilege / attenuation:** child grants are subsets of parent authority.
- **Delegation-chain validation:** contextual and semantic modes reject missing, broadened, inconsistent, or over-depth grants.
- **Task and purpose binding:** actions must match the trusted task contract.
- **Contextual resource and destination checks:** data and outputs stay within task scope and approved destinations.
- **Composition controls:** confidential reads cannot be followed by external disclosure.
- **Semantic risk checks:** classify content and assess purpose/recipient risk; model output can flag or deny but cannot grant authority.
- **Audit evidence:** each authorization decision is recorded in a hash-chained SQLite log.
- **Tool boundary enforcement:** authorization runs inside the resource tool boundary; instructions and tool visibility are not treated as permission checks.

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
attack_cases.py
audit.py
context.py
test_lab.py
requirements.txt
.env.example
.gitignore
README.md
```

This prototype is intended for instruction, not production authorization.
