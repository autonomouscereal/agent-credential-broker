---
name: agent-credential-broker
description: Deploy, test, or integrate a local secretless credential broker for AI agents. Use when agents need scoped credential leases, vault-backed provider actions without seeing secrets, brokered access to APIs, least-privilege credential handling, approval-gated access, or a standalone proof of concept for secure agent credential use.
---

# Agent Credential Broker

Use this skill when an agent must use credentials or user-provided sensitive values without receiving or reading the value.

## Workflow

1. Read `README.md`, `docs/security-review.md`, and `docs/sensitive-intake.md`.
2. Generate `BROKER_MASTER_KEY` with `python src/broker.py generate-key`.
3. Create `.env` from `.env.example` and set generated secrets.
4. Start PostgreSQL with `docker compose up -d postgres`.
5. Run `python src/broker.py init`.
6. Run tests with `python -m unittest discover -s tests` and compile with `python -m py_compile src/broker.py`.
7. Serve locally with `python src/broker.py serve`.
8. Store credentials through `/admin/secret`, grant leases through `/admin/grant`, and let agents use provider adapters with lease tokens.
9. For user-provided protected values, create a form through `/intake/request`, send the user the `form_url`, poll `/intake/status`, and pass only `value_ref` references to provider adapters.

## Rules

- Do not expose a generic vault read endpoint to agents.
- Do not pass secrets through environment variables to arbitrary model-controlled commands.
- Do not print raw secrets in logs, audit rows, traces, docs, or chat.
- Do not ask users to paste protected values into chat, email, ticket notes, prompts, logs, or memory.
- Keep provider adapters narrow and resource/action scoped.
- Use short TTLs and explicit revocation in production.
- Use one-use sensitive intake forms for user-provided protected values.
- Bind to localhost by default; add TLS/auth proxy before network exposure.
- Back up encrypted vault state and master key separately.

## Good Agent Behavior

When denied, create an access request for the exact `system`, `resource_type`, `resource_id`, and `action`. Do not work around the control.
