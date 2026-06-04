# Sensitive Intake Forms

Sensitive intake handles a leak path that scoped credential leases alone do not
solve: a user may paste passwords, recovery codes, API keys, SSNs, HR data, or
other protected values into chat, email, tickets, logs, model prompts, browser
captures, or memory because an agent asked for them naturally.

Filtering and DLP are useful, but they are not a complete control. The safer
pattern is to move the value entry out of the agent transcript entirely.

## Pattern

1. The agent creates a short-lived intake request with exact field keys, labels,
   descriptions, and field types.
2. The broker returns a one-use `form_url` plus an `intake_ref`.
3. The agent pastes the form link into chat, email, or a ticket, but never asks
   the user to paste values into the conversation.
4. The user submits values through the broker-hosted form.
5. The broker validates required fields, encrypts each submitted value, marks
   the form as submitted, and records redacted audit evidence.
6. The agent polls status and receives only labels and `value_ref` references.
7. A narrow provider adapter resolves the encrypted values inside the broker
   process and returns only safe evidence.

The agent can coordinate the work without seeing the submitted values.

## Screenshots

![Secure intake form](assets/secure-intake-form.png)

![Secure intake submitted](assets/secure-intake-submitted.png)

## API Flow

Create a request:

```bash
curl -sS -X POST http://127.0.0.1:8766/intake/request \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-1",
    "purpose": "Collect temporary account proof without putting sensitive values in chat, tickets, logs, or memory.",
    "ttl_seconds": 600,
    "fields": [
      {
        "key": "temporary_password",
        "label": "Temporary password",
        "type": "password",
        "required": true,
        "description": "Use a short-lived value for this request."
      },
      {
        "key": "otp_code",
        "label": "One-time code",
        "type": "text",
        "required": true,
        "description": "Example second factor or recovery code."
      }
    ]
  }'
```

The response includes a form URL and no submitted values:

```json
{
  "request_ref": "intake_example",
  "agent_id": "agent-1",
  "status": "pending",
  "form_url": "http://127.0.0.1:8766/forms/<one-use-token>",
  "secret_values_returned": false
}
```

After the user submits the form, the agent checks status:

```bash
curl -sS -X POST http://127.0.0.1:8766/intake/status \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-1","request_ref":"intake_example"}'
```

The agent receives references only:

```json
{
  "request_ref": "intake_example",
  "status": "submitted",
  "fields": [
    {
      "key": "temporary_password",
      "label": "Temporary password",
      "value_ref": "intake_example:temporary_password",
      "submitted": true
    }
  ],
  "secret_values_returned": false
}
```

To demonstrate provider-side use, grant the agent a lease for the intake
resource:

```bash
curl -sS -X POST http://127.0.0.1:8766/admin/grant \
  -H "Content-Type: application/json" \
  -H "X-Broker-Service-Token: $BROKER_SERVICE_TOKEN" \
  -d '{
    "agent_id": "agent-1",
    "system": "demo",
    "resource_type": "intake",
    "resource_id": "intake_example",
    "action": "use",
    "ttl_seconds": 600
  }'
```

Then the agent requests a lease token and calls the demo provider route:

```bash
LEASE_TOKEN=$(curl -sS -X POST http://127.0.0.1:8766/leases/request \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-1","system":"demo","resource_type":"intake","resource_id":"intake_example","action":"use"}' |
  python -c "import sys,json; print(json.load(sys.stdin)['lease_token'])")

curl -sS -X POST http://127.0.0.1:8766/provider/demo/use-intake \
  -H "Content-Type: application/json" \
  -d "{\"lease_token\":\"$LEASE_TOKEN\",\"intake_ref\":\"intake_example\"}"
```

The provider uses the decrypted values inside the broker and returns only
evidence:

```json
{
  "ok": true,
  "provider": "demo",
  "intake_ref": "intake_example",
  "fields_received": ["otp_code", "temporary_password"],
  "secret_values_returned": false
}
```

## Production Notes

- Treat the form URL as a bearer submission link. Keep TTLs short and put the
  broker behind TLS and authenticated routing before network exposure.
- Bind the form to the requester identity when your chat/email/ticketing system
  can authenticate the user.
- Do not add an agent-callable endpoint that returns decrypted intake values.
- Keep provider adapters narrow and action scoped.
- Store only labels, references, status, and redacted audit evidence in tickets,
  prompts, logs, and memory.
- Use one-use forms. If the user enters the wrong value, create a fresh request.
