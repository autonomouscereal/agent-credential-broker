# Security Review And Comparable Patterns

## Existing Agentic Operations Lease Pattern

The dashboard pattern is directionally sound:

- Agents receive scoped lease references, not raw secret values.
- Leases are keyed by agent, system, resource type, resource id, and action.
- Provider routes validate the active lease at use time.
- Denials produce permission walls and access-request workflow instead of silent bypass.
- Lease grants are tied to approval evidence.
- Provider routes return `credential_value: null` / `secret_values_returned: false`.
- Audit events record allow/deny decisions and provider access.

Important risks to keep watching:

- A lease reference is not enough if agents can also read the underlying vault directly.
- A lease reference is not enough if users paste protected values into agent-visible chats, tickets, prompts, logs, screenshots, or memory.
- Wildcard resource ids should be rare and short-lived.
- Provider adapters must be narrow; a generic shell endpoint with secrets in env would let the agent print them.
- Lease tokens/references should expire and be revocable.
- Logs, traces, browser captures, and tool outputs need redaction.
- Approval gates should include resource/action evidence, not just human prose.
- Broker/service tokens must never be exposed to model workspaces.

## Sensitive Intake Form Pattern

The broker now includes a generalized secure form flow for user-provided values
that should not enter the model transcript at all.

This is meant for cases like:

- temporary passwords
- one-time codes or recovery codes
- user-provided API keys
- protected HR, finance, legal, or identity values
- any value that would be harmful if copied into chat, email, tickets, logs, or memory

The important control is not the HTML form itself. The control is the data
boundary:

1. Agent creates a request with field metadata only.
2. User submits values through a short-lived one-use form.
3. Broker validates fields and stores encrypted values.
4. Agent polls status and receives `value_ref` entries only.
5. Provider adapters resolve values inside the broker after scoped lease checks.
6. Provider responses return evidence and `secret_values_returned: false`.

Production hardening should add authenticated requester binding, TLS, request
rate limits, form submission provenance, stronger revocation controls, and
organization-specific retention rules. Do not expose a route that lets agents
retrieve decrypted intake values.

## How This Maps To The Wild

HashiCorp Vault dynamic secrets:
- Similar idea: short-lived, leased credentials with renewal/revocation.
- Difference: many Vault Agent flows still render secrets onto the client filesystem. This repo avoids that by keeping secrets inside provider adapters.
- Reference: https://developer.hashicorp.com/vault/docs/secrets

AWS STS and IAM Roles Anywhere:
- Similar idea: workloads use identity to obtain temporary credentials.
- Difference: the workload often receives temporary credentials. This broker can go further by returning only an operation result.
- References: https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html and https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html

SPIFFE/SPIRE workload identity:
- Similar idea: verifiable workload identity, short-lived SVIDs, and policy-bound access.
- Best production path: use workload identity to authenticate the broker and agents, then broker operation access by policy.
- Reference: https://spiffe.io/docs/latest/spiffe-about/overview/

OIDC workload federation:
- Similar idea: agent or runner identity is exchanged for scoped access without static keys.
- Good fit for CI/CD and cloud APIs when the provider supports it.
- Reference: https://openid.net/specs/openid-connect-core-1_0.html

Secretless brokers and sidecars:
- Similar idea: application talks to a local proxy, proxy handles credentials.
- For AI agents, keep the proxy/provider surface narrow and auditable because the model can intentionally try unexpected calls.

## Recommendation

Use a layered model:

1. Workload identity authenticates the agent runtime.
2. Policy grants scoped leases with short TTL.
3. Provider adapters execute narrow operations server-side.
4. Broker returns data, evidence, and audit ids, never credentials.
5. Approval/access-request workflows mint leases only after human or policy approval.
6. Sensitive intake forms collect user-provided protected values without putting them into the agent transcript.
7. Disaster recovery backs up encrypted vault state and master keys separately.
