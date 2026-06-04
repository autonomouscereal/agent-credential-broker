CREATE TABLE IF NOT EXISTS broker_secrets (
    id BIGSERIAL PRIMARY KEY,
    system TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'read',
    encrypted_secret TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(system, resource_type, resource_id, action)
);

CREATE TABLE IF NOT EXISTS broker_leases (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    system TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'read',
    lease_status TEXT NOT NULL DEFAULT 'active',
    expires_at TIMESTAMPTZ NOT NULL,
    granted_by TEXT NOT NULL DEFAULT 'operator',
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS broker_audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    details JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS sensitive_intake_requests (
    id BIGSERIAL PRIMARY KEY,
    request_ref TEXT NOT NULL UNIQUE,
    agent_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    fields JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    token_hash TEXT NOT NULL UNIQUE,
    form_path TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    submitted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sensitive_intake_values (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL REFERENCES sensitive_intake_requests(id) ON DELETE CASCADE,
    field_key TEXT NOT NULL,
    label TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    value_ref TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(request_id, field_key)
);

CREATE INDEX IF NOT EXISTS idx_broker_leases_lookup
    ON broker_leases(agent_id, system, resource_type, action, lease_status, expires_at);
CREATE INDEX IF NOT EXISTS idx_broker_audit_created
    ON broker_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sensitive_intake_requests_agent
    ON sensitive_intake_requests(agent_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_sensitive_intake_values_request
    ON sensitive_intake_values(request_id);
