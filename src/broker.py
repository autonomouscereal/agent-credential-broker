#!/usr/bin/env python3
"""Local secretless credential broker proof of concept.

Raw psycopg2 only. No ORM, no SQLAlchemy, no Pydantic.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema" / "001_init.sql"
SECRET_KEY_MARKERS = {"secret", "password", "token", "authorization", "cookie", "api_key", "private_key", "passphrase", "credential"}
SECRET_KEYS = SECRET_KEY_MARKERS | {
    "value",
    "values",
    "raw_value",
    "raw_values",
    "submitted_value",
    "submitted_values",
    "sensitive_value",
    "sensitive_values",
}
SAFE_EVIDENCE_KEYS = {"credential_injected", "secret_values_returned"}
FIELD_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
INTAKE_FIELD_TYPES = {"text", "password", "email", "number", "textarea"}


def db_params() -> dict[str, Any]:
    return {
        "host": os.getenv("BROKER_DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("BROKER_DB_PORT", "25491")),
        "dbname": os.getenv("BROKER_DB_NAME", "agent_credential_broker"),
        "user": os.getenv("BROKER_DB_USER", "credential_broker"),
        "password": os.getenv("BROKER_DB_PASSWORD") or os.getenv("PGPASSWORD"),
    }


def connect():
    params = db_params()
    if not params.get("password"):
        raise RuntimeError("Set BROKER_DB_PASSWORD or PGPASSWORD before connecting.")
    return psycopg2.connect(**params)


def fernet() -> Fernet:
    key = os.getenv("BROKER_MASTER_KEY")
    if not key:
        raise RuntimeError("Set BROKER_MASTER_KEY. Generate one with: python src/broker.py generate-key")
    return Fernet(key.encode("utf-8"))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            lower = str(key).lower()
            if lower == "lease_token":
                clean[key] = item
                continue
            if lower in SAFE_EVIDENCE_KEYS:
                clean[key] = item
                continue
            if lower in SECRET_KEYS or any(marker in lower for marker in SECRET_KEY_MARKERS):
                clean[key] = "<redacted>"
            else:
                clean[key] = redact(item)
        return clean
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def scope_matches(lease: dict[str, Any], system: str, resource_type: str, resource_id: str, action: str) -> bool:
    return (
        lease.get("system") == system
        and lease.get("resource_type") == resource_type
        and fnmatch.fnmatch(str(resource_id), str(lease.get("resource_id") or "*"))
        and (lease.get("action") == action or lease.get("action") == "*")
    )


def issue_lease_token(lease: dict[str, Any], ttl_seconds: int = 300) -> str:
    exp = min(int(time.time()) + ttl_seconds, int(lease["expires_at"].timestamp()))
    claims = {
        "lease_id": lease["id"],
        "agent_id": lease["agent_id"],
        "system": lease["system"],
        "resource_type": lease["resource_type"],
        "resource_id": lease["resource_id"],
        "action": lease["action"],
        "exp": exp,
    }
    return fernet().encrypt(json.dumps(claims, sort_keys=True).encode("utf-8")).decode("utf-8")


def verify_lease_token(token: str) -> dict[str, Any]:
    try:
        claims = json.loads(fernet().decrypt(token.encode("utf-8"), ttl=None).decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError) as exc:
        raise PermissionError("invalid_lease_token") from exc
    if int(claims.get("exp", 0)) <= int(time.time()):
        raise PermissionError("expired_lease_token")
    return claims


def audit(actor: str, action: str, target: str, decision: str, reason: str = "", details: dict[str, Any] | None = None) -> None:
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO broker_audit_log (actor, action, target, decision, reason, details)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            """,
            (actor, action, target, decision, reason, json.dumps(redact(details or {}), default=str)),
        )


def store_secret(payload: dict[str, Any]) -> dict[str, Any]:
    required = ["system", "resource_type", "resource_id", "action", "secret_value"]
    missing = [key for key in required if not payload.get(key)]
    if missing:
        raise ValueError(f"missing fields: {', '.join(missing)}")
    encrypted = fernet().encrypt(str(payload["secret_value"]).encode("utf-8")).decode("utf-8")
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO broker_secrets (system, resource_type, resource_id, action, encrypted_secret)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (system, resource_type, resource_id, action)
            DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, updated_at = NOW()
            RETURNING id, system, resource_type, resource_id, action, created_at, updated_at
            """,
            (payload["system"], payload["resource_type"], payload["resource_id"], payload["action"], encrypted),
        )
        row = dict(cur.fetchone())
    audit("operator", "secret_upsert", f"{row['system']}:{row['resource_type']}:{row['resource_id']}", "allow")
    return row


def grant_lease(payload: dict[str, Any]) -> dict[str, Any]:
    ttl = int(payload.get("ttl_seconds") or 300)
    ttl = max(30, min(ttl, 3600))
    expires_at = utcnow() + timedelta(seconds=ttl)
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO broker_leases (
                agent_id, system, resource_type, resource_id, action,
                lease_status, expires_at, granted_by, reason
            )
            VALUES (%s, %s, %s, %s, %s, 'active', %s, %s, %s)
            RETURNING *
            """,
            (
                payload["agent_id"],
                payload["system"],
                payload.get("resource_type") or "resource",
                payload.get("resource_id") or "*",
                payload.get("action") or "read",
                expires_at,
                payload.get("granted_by") or "operator",
                payload.get("reason") or "",
            ),
        )
        lease = dict(cur.fetchone())
    audit("operator", "lease_grant", f"lease_{lease['id']}", "allow", details=lease)
    return {key: value for key, value in lease.items() if key != "encrypted_secret"}


def request_lease(payload: dict[str, Any]) -> dict[str, Any]:
    agent_id = payload["agent_id"]
    system = payload["system"]
    resource_type = payload.get("resource_type") or "resource"
    resource_id = payload.get("resource_id") or "*"
    action = payload.get("action") or "read"
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT *
            FROM broker_leases
            WHERE agent_id = %s
              AND system = %s
              AND resource_type = %s
              AND action IN (%s, '*')
              AND lease_status = 'active'
              AND expires_at > NOW()
            ORDER BY expires_at DESC
            """,
            (agent_id, system, resource_type, action),
        )
        rows = [dict(row) for row in cur.fetchall()]
    for lease in rows:
        if scope_matches(lease, system, resource_type, resource_id, action):
            token = issue_lease_token(lease)
            audit(agent_id, "lease_request", f"lease_{lease['id']}", "allow", "scope_match", lease)
            return {
                "allow": True,
                "lease_id": lease["id"],
                "lease_token": token,
                "expires_at": lease["expires_at"].isoformat(),
                "secret_values_returned": False,
            }
    audit(agent_id, "lease_request", f"{system}:{resource_type}:{resource_id}:{action}", "deny", "missing_active_lease", payload)
    return {"allow": False, "error": "missing_active_lease", "secret_values_returned": False}


def load_secret_for_claims(claims: dict[str, Any]) -> str:
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT encrypted_secret
            FROM broker_secrets
            WHERE system = %s AND resource_type = %s AND resource_id = %s AND action = %s
            """,
            (claims["system"], claims["resource_type"], claims["resource_id"], claims["action"]),
        )
        row = cur.fetchone()
    if not row:
        raise LookupError("no_secret_for_scope")
    return fernet().decrypt(row["encrypted_secret"].encode("utf-8")).decode("utf-8")


def hash_form_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def public_base_url() -> str:
    configured = os.getenv("BROKER_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    host = os.getenv("BROKER_HOST", "127.0.0.1")
    port = int(os.getenv("BROKER_PORT", "8766"))
    return f"http://{host}:{port}"


def public_form_url(form_path: str) -> str:
    return f"{public_base_url()}{form_path}"


def normalize_intake_fields(fields: Any) -> list[dict[str, Any]]:
    if not isinstance(fields, list) or not fields:
        raise ValueError("fields must be a non-empty list")
    if len(fields) > 20:
        raise ValueError("secure intake supports at most 20 fields per request")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in fields:
        if not isinstance(item, dict):
            raise ValueError("each field must be an object")
        key = str(item.get("key") or "").strip()
        if not FIELD_KEY_RE.fullmatch(key):
            raise ValueError("field keys must be 1-64 chars: letters, numbers, dots, underscores, or dashes")
        if key in seen:
            raise ValueError(f"duplicate field key: {key}")
        seen.add(key)
        label = str(item.get("label") or key).strip()
        if not label:
            raise ValueError(f"field {key} is missing a label")
        field_type = str(item.get("type") or "text").strip().lower()
        if field_type not in INTAKE_FIELD_TYPES:
            raise ValueError(f"unsupported field type for {key}: {field_type}")
        normalized.append({
            "key": key,
            "label": label[:120],
            "type": field_type,
            "required": bool(item.get("required", True)),
            "description": str(item.get("description") or "").strip()[:240],
        })
    return normalized


def parse_jsonb(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def is_expired(expires_at: Any) -> bool:
    if not expires_at:
        return False
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
    if getattr(expires_at, "tzinfo", None) is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= utcnow()


def intake_status_payload(request: dict[str, Any], values: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    fields = parse_jsonb(request.get("fields"), [])
    status = request.get("status") or "pending"
    if status == "pending" and is_expired(request.get("expires_at")):
        status = "expired"
    value_map = {row["field_key"]: row for row in values or []}
    safe_fields = []
    for field in fields:
        item = {
            "key": field["key"],
            "label": field["label"],
            "type": field.get("type") or "text",
            "required": bool(field.get("required", True)),
            "description": field.get("description") or "",
        }
        if field["key"] in value_map:
            item["value_ref"] = value_map[field["key"]]["value_ref"]
            item["submitted"] = True
        else:
            item["submitted"] = False
        safe_fields.append(item)
    return {
        "request_ref": request["request_ref"],
        "agent_id": request["agent_id"],
        "purpose": request["purpose"],
        "status": status,
        "fields": safe_fields,
        "expires_at": request["expires_at"],
        "submitted_at": request.get("submitted_at"),
        "secret_values_returned": False,
    }


def create_intake_request(payload: dict[str, Any]) -> dict[str, Any]:
    agent_id = str(payload.get("agent_id") or "").strip()
    purpose = str(payload.get("purpose") or "").strip()
    if not agent_id:
        raise ValueError("agent_id is required")
    if not purpose:
        raise ValueError("purpose is required")
    fields = normalize_intake_fields(payload.get("fields"))
    ttl = int(payload.get("ttl_seconds") or 3600)
    ttl = max(60, min(ttl, 86400))
    request_ref = f"intake_{secrets.token_urlsafe(12).replace('-', '_')}"
    form_token = secrets.token_urlsafe(32)
    form_path = f"/forms/{form_token}"
    expires_at = utcnow() + timedelta(seconds=ttl)
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO sensitive_intake_requests (
                request_ref, agent_id, purpose, fields, status, token_hash, form_path, expires_at
            )
            VALUES (%s, %s, %s, %s::jsonb, 'pending', %s, %s, %s)
            RETURNING *
            """,
            (request_ref, agent_id, purpose[:240], json.dumps(fields), hash_form_token(form_token), form_path, expires_at),
        )
        request = dict(cur.fetchone())
    audit(agent_id, "sensitive_intake_create", request_ref, "allow", details={
        "purpose": purpose[:240],
        "field_keys": [field["key"] for field in fields],
        "ttl_seconds": ttl,
    })
    result = intake_status_payload(request)
    result["form_url"] = public_form_url(form_path)
    return result


def load_intake_by_token(cur: Any, token: str, for_update: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    cur.execute(
        f"""
        SELECT *
        FROM sensitive_intake_requests
        WHERE token_hash = %s
        {suffix}
        """,
        (hash_form_token(token),),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def get_intake_status(payload: dict[str, Any]) -> dict[str, Any]:
    agent_id = str(payload.get("agent_id") or "").strip()
    request_ref = str(payload.get("request_ref") or "").strip()
    if not agent_id or not request_ref:
        raise ValueError("agent_id and request_ref are required")
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT *
            FROM sensitive_intake_requests
            WHERE agent_id = %s AND request_ref = %s
            """,
            (agent_id, request_ref),
        )
        request = cur.fetchone()
        if not request:
            raise LookupError("intake_request_not_found")
        cur.execute(
            """
            SELECT field_key, label, value_ref
            FROM sensitive_intake_values
            WHERE request_id = %s
            ORDER BY id
            """,
            (request["id"],),
        )
        values = [dict(row) for row in cur.fetchall()]
    return intake_status_payload(dict(request), values)


def render_intake_form(request: dict[str, Any], error: str = "") -> str:
    fields = parse_jsonb(request.get("fields"), [])
    status = request.get("status") or "pending"
    expired = status == "pending" and is_expired(request.get("expires_at"))
    title = "Secure Intake"
    if status == "submitted":
        body = """
        <section class="panel success">
          <h1>Secure intake submitted</h1>
          <p>The broker encrypted your values and returned only field references to the agent.</p>
        </section>
        """
    elif expired:
        body = """
        <section class="panel">
          <h1>Secure intake expired</h1>
          <p>This one-use form is no longer active. Ask the agent to create a fresh request.</p>
        </section>
        """
    else:
        controls = []
        for field in fields:
            key = html.escape(field["key"], quote=True)
            label = html.escape(field["label"])
            desc = html.escape(field.get("description") or "")
            required = " required" if field.get("required", True) else ""
            input_type = html.escape(field.get("type") or "text", quote=True)
            help_text = f'<p class="help">{desc}</p>' if desc else ""
            if input_type == "textarea":
                control = f'<textarea id="{key}" name="{key}" rows="4"{required} autocomplete="off"></textarea>'
            else:
                control = f'<input id="{key}" name="{key}" type="{input_type}"{required} autocomplete="off" />'
            controls.append(f"""
            <label class="field" for="{key}">
              <span>{label}</span>
              {help_text}
              {control}
            </label>
            """)
        error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
        body = f"""
        <section class="panel">
          <p class="eyebrow">Agent Credential Broker</p>
          <h1>{title}</h1>
          <p class="purpose">{html.escape(request.get("purpose") or "")}</p>
          {error_html}
          <form method="post">
            {''.join(controls)}
            <button type="submit">Submit securely</button>
          </form>
          <p class="fine-print">Values are encrypted by the broker. The agent receives references, not the submitted values.</p>
        </section>
        """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; min-height: 100vh; background: #f4f6f8; color: #17202a; display: grid; place-items: center; padding: 32px; }}
    .panel {{ width: min(680px, 100%); background: #ffffff; border: 1px solid #d8dee6; border-radius: 8px; box-shadow: 0 20px 60px rgba(30, 41, 59, 0.12); padding: 32px; }}
    .panel.success {{ border-color: #7bc89a; }}
    .eyebrow {{ margin: 0 0 8px; color: #526273; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0; }}
    h1 {{ margin: 0; font-size: 30px; line-height: 1.15; letter-spacing: 0; }}
    .purpose {{ margin: 12px 0 24px; color: #3f4d5a; line-height: 1.5; }}
    .field {{ display: block; margin: 0 0 18px; font-weight: 700; }}
    .help {{ margin: 6px 0 8px; color: #657385; font-size: 14px; font-weight: 400; line-height: 1.45; }}
    input, textarea {{ box-sizing: border-box; width: 100%; margin-top: 8px; border: 1px solid #b9c3cf; border-radius: 6px; padding: 12px 13px; font: inherit; background: #fbfcfd; color: #17202a; }}
    input:focus, textarea:focus {{ outline: 3px solid #b8d7ff; border-color: #3978bd; background: #ffffff; }}
    button {{ border: 0; border-radius: 6px; background: #1f6f8b; color: #ffffff; font: inherit; font-weight: 800; padding: 12px 18px; cursor: pointer; }}
    button:hover {{ background: #185d75; }}
    .fine-print {{ margin: 18px 0 0; color: #657385; font-size: 13px; line-height: 1.45; }}
    .error {{ border: 1px solid #d87979; background: #fff2f2; color: #812626; border-radius: 6px; padding: 10px 12px; }}
  </style>
</head>
<body>
  {body}
</body>
</html>"""


def submit_intake_form(token: str, submitted_values: dict[str, Any]) -> dict[str, Any]:
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        request = load_intake_by_token(cur, token, for_update=True)
        if not request:
            raise LookupError("intake_request_not_found")
        if request["status"] != "pending":
            raise PermissionError("intake_request_already_used")
        if is_expired(request["expires_at"]):
            cur.execute(
                "UPDATE sensitive_intake_requests SET status = 'expired', updated_at = NOW() WHERE id = %s",
                (request["id"],),
            )
            raise PermissionError("intake_request_expired")
        fields = parse_jsonb(request.get("fields"), [])
        missing = []
        encrypted_rows = []
        for field in fields:
            key = field["key"]
            raw = submitted_values.get(key)
            if isinstance(raw, list):
                raw = raw[0] if raw else ""
            if raw is None or str(raw) == "":
                if field.get("required", True):
                    missing.append(field["label"])
                continue
            value_ref = f"{request['request_ref']}:{key}"
            encrypted_rows.append({
                "field_key": key,
                "label": field["label"],
                "encrypted_value": fernet().encrypt(str(raw).encode("utf-8")).decode("utf-8"),
                "value_ref": value_ref,
            })
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        if not encrypted_rows:
            raise ValueError("no values submitted")
        for row in encrypted_rows:
            cur.execute(
                """
                INSERT INTO sensitive_intake_values (
                    request_id, field_key, label, encrypted_value, value_ref
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (request["id"], row["field_key"], row["label"], row["encrypted_value"], row["value_ref"]),
            )
        cur.execute(
            """
            UPDATE sensitive_intake_requests
            SET status = 'submitted', submitted_at = NOW(), updated_at = NOW()
            WHERE id = %s
            RETURNING *
            """,
            (request["id"],),
        )
        updated = dict(cur.fetchone())
    audit("user", "sensitive_intake_submit", updated["request_ref"], "allow", details={
        "field_keys": [row["field_key"] for row in encrypted_rows],
        "value_refs": [row["value_ref"] for row in encrypted_rows],
        "secret_values_returned": False,
    })
    return intake_status_payload(updated, encrypted_rows)


def resolve_intake_values(request_ref: str) -> dict[str, str]:
    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, status
            FROM sensitive_intake_requests
            WHERE request_ref = %s
            """,
            (request_ref,),
        )
        request = cur.fetchone()
        if not request:
            raise LookupError("intake_request_not_found")
        if request["status"] != "submitted":
            raise PermissionError("intake_request_not_submitted")
        cur.execute(
            """
            SELECT field_key, encrypted_value
            FROM sensitive_intake_values
            WHERE request_id = %s
            ORDER BY id
            """,
            (request["id"],),
        )
        rows = [dict(row) for row in cur.fetchall()]
    return {
        row["field_key"]: fernet().decrypt(row["encrypted_value"].encode("utf-8")).decode("utf-8")
        for row in rows
    }


def demo_provider_read(payload: dict[str, Any]) -> dict[str, Any]:
    claims = verify_lease_token(payload["lease_token"])
    if not scope_matches(claims, "demo", "dataset", claims["resource_id"], "read"):
        raise PermissionError("lease_not_valid_for_demo_read")
    secret = load_secret_for_claims(claims)
    if not secret:
        raise PermissionError("empty_secret")
    audit(claims["agent_id"], "provider_demo_read", f"demo:dataset:{claims['resource_id']}", "allow", details={
        "lease_id": claims["lease_id"],
        "query": payload.get("query", ""),
        "credential_injected": True,
        "secret_values_returned": False,
    })
    return {
        "ok": True,
        "agent_id": claims["agent_id"],
        "lease_id": claims["lease_id"],
        "provider": "demo",
        "data": {
            "credential_injected": True,
            "query": payload.get("query", ""),
            "message": "demo provider read succeeded through broker-owned credential injection",
        },
        "secret_values_returned": False,
    }


def demo_provider_use_intake(payload: dict[str, Any]) -> dict[str, Any]:
    claims = verify_lease_token(payload["lease_token"])
    intake_ref = str(payload.get("intake_ref") or "").strip()
    if not intake_ref:
        raise ValueError("intake_ref is required")
    if not scope_matches(claims, "demo", "intake", intake_ref, "use"):
        raise PermissionError("lease_not_valid_for_demo_intake_use")
    values = resolve_intake_values(intake_ref)
    field_keys = sorted(values.keys())
    audit(claims["agent_id"], "provider_demo_use_intake", f"demo:intake:{intake_ref}", "allow", details={
        "lease_id": claims["lease_id"],
        "field_keys": field_keys,
        "value_refs": [f"{intake_ref}:{key}" for key in field_keys],
        "secret_values_returned": False,
    })
    return {
        "ok": True,
        "agent_id": claims["agent_id"],
        "lease_id": claims["lease_id"],
        "provider": "demo",
        "intake_ref": intake_ref,
        "fields_received": field_keys,
        "message": "demo provider used sensitive intake values inside the broker and returned only evidence",
        "secret_values_returned": False,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentCredentialBroker/0.1"

    def _body_bytes(self) -> bytes:
        size = int(self.headers.get("content-length") or "0")
        return self.rfile.read(size) if size else b"{}"

    def _json(self) -> dict[str, Any]:
        raw = self._body_bytes().decode("utf-8")
        return json.loads(raw or "{}")

    def _form(self) -> dict[str, Any]:
        content_type = self.headers.get("content-type", "")
        raw = self._body_bytes().decode("utf-8")
        if "application/json" in content_type:
            payload = json.loads(raw or "{}")
            return payload if isinstance(payload, dict) else {}
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[0] if values else "" for key, values in parsed.items()}

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(redact(payload), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _admin_allowed(self) -> bool:
        expected = os.getenv("BROKER_SERVICE_TOKEN", "")
        provided = self.headers.get("x-broker-service-token", "")
        return bool(expected) and provided == expected

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, {"status": "ok"})
        elif path.startswith("/forms/"):
            token = unquote(path.removeprefix("/forms/"))
            with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                request = load_intake_by_token(cur, token)
            if not request:
                self._send_html(404, render_intake_form({"status": "expired", "fields": [], "purpose": ""}))
                return
            self._send_html(200, render_intake_form(request))
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            if path.startswith("/forms/"):
                token = unquote(path.removeprefix("/forms/"))
                try:
                    submit_intake_form(token, self._form())
                    self._send_html(200, render_intake_form({"status": "submitted", "fields": [], "purpose": ""}))
                except ValueError as exc:
                    with connect() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        request = load_intake_by_token(cur, token)
                    if not request:
                        self._send_html(404, render_intake_form({"status": "expired", "fields": [], "purpose": ""}))
                    else:
                        self._send_html(400, render_intake_form(request, error=str(exc)))
                return
            if path.startswith("/admin/") and not self._admin_allowed():
                self._send(403, {"error": "admin_token_required"})
                return
            payload = self._json()
            if path == "/admin/secret":
                self._send(200, store_secret(payload))
            elif path == "/admin/grant":
                self._send(200, grant_lease(payload))
            elif path == "/leases/request":
                result = request_lease(payload)
                self._send(200 if result.get("allow") else 403, result)
            elif path == "/intake/request":
                self._send(200, create_intake_request(payload))
            elif path == "/intake/status":
                self._send(200, get_intake_status(payload))
            elif path == "/provider/demo/read":
                self._send(200, demo_provider_read(payload))
            elif path == "/provider/demo/use-intake":
                self._send(200, demo_provider_use_intake(payload))
            else:
                self._send(404, {"error": "not_found"})
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except PermissionError as exc:
            self._send(403, {"error": str(exc)})
        except LookupError as exc:
            self._send(404, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": "broker_error", "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def cmd_generate_key(_: argparse.Namespace) -> None:
    print(Fernet.generate_key().decode("utf-8"))


def cmd_init(_: argparse.Namespace) -> None:
    with connect() as conn, conn.cursor() as cur:
        cur.execute(SCHEMA.read_text(encoding="utf-8"))
    print("initialized")


def cmd_serve(_: argparse.Namespace) -> None:
    host = os.getenv("BROKER_HOST", "127.0.0.1")
    port = int(os.getenv("BROKER_PORT", "8766"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"serving on http://{host}:{port}", file=sys.stderr)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate-key").set_defaults(func=cmd_generate_key)
    sub.add_parser("init").set_defaults(func=cmd_init)
    sub.add_parser("serve").set_defaults(func=cmd_serve)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
