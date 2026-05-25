#!/usr/bin/env python3
"""Local secretless credential broker proof of concept.

Raw psycopg2 only. No ORM, no SQLAlchemy, no Pydantic.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema" / "001_init.sql"
SECRET_KEYS = {"secret", "secret_value", "password", "token", "authorization", "cookie", "api_key"}


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
            if lower in SECRET_KEYS or any(marker in lower for marker in SECRET_KEYS):
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
    if int(claims.get("exp", 0)) < int(time.time()):
        raise PermissionError("expired_lease_token")
    return claims


def audit(actor: str, action: str, target: str, decision: str, reason: str = "", details: dict[str, Any] | None = None) -> None:
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO broker_audit_log (actor, action, target, decision, reason, details)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            """,
            (actor, action, target, decision, reason, json.dumps(redact(details or {}))),
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


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentCredentialBroker/0.1"

    def _json(self) -> dict[str, Any]:
        size = int(self.headers.get("content-length") or "0")
        raw = self.rfile.read(size).decode("utf-8") if size else "{}"
        return json.loads(raw or "{}")

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(redact(payload), default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _admin_allowed(self) -> bool:
        expected = os.getenv("BROKER_SERVICE_TOKEN", "")
        provided = self.headers.get("x-broker-service-token", "")
        return bool(expected) and provided == expected

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            if self.path.startswith("/admin/") and not self._admin_allowed():
                self._send(403, {"error": "admin_token_required"})
                return
            payload = self._json()
            if self.path == "/admin/secret":
                self._send(200, store_secret(payload))
            elif self.path == "/admin/grant":
                self._send(200, grant_lease(payload))
            elif self.path == "/leases/request":
                result = request_lease(payload)
                self._send(200 if result.get("allow") else 403, result)
            elif self.path == "/provider/demo/read":
                self._send(200, demo_provider_read(payload))
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
