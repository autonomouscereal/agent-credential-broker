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
- Wildcard resource ids should be rare and short-lived.
- Provider adapters must be narrow; a generic shell endpoint with secrets in env would let the agent print them.
- Lease tokens/references should expire and be revocable.
- Logs, traces, browser captures, and tool outputs need redaction.
- Approval gates should include resource/action evidence, not just human prose.
- Broker/service tokens must never be exposed to model workspaces.

## How This Maps To The Wild

HashiCorp Vault dynamic secrets:
- Similar idea: short-lived, leased credentials with renewal/revocation.
- Difference: many Vault Agent flows still render secrets onto the client filesystem. This repo avoids that by keeping secrets inside provider adapters.

AWS STS and IAM Roles Anywhere:
- Similar idea: workloads use identity to obtain temporary credentials.
- Difference: the workload often receives temporary credentials. This broker can go further by returning only an operation result.

SPIFFE/SPIRE workload identity:
- Similar idea: verifiable workload identity, short-lived SVIDs, and policy-bound access.
- Best production path: use workload identity to authenticate the broker and agents, then broker operation access by policy.

OIDC workload federation:
- Similar idea: agent or runner identity is exchanged for scoped access without static keys.
- Good fit for CI/CD and cloud APIs when the provider supports it.

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
6. Disaster recovery backs up encrypted vault state and master keys separately.
