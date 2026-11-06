import hashlib
import json
import sqlite3
import uuid
from pathlib import Path

from models import ActionRequest, Decision, utc_now


class AuditLog:
    """Small SQLite audit log with a tamper-evident SHA-256 event chain."""

    def __init__(self, db_path: str = "lab_audit.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True) if Path(db_path).parent != Path(".") else None
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    timestamp TEXT,
                    agent_id TEXT,
                    action TEXT,
                    resource TEXT,
                    purpose TEXT,
                    decision TEXT,
                    reason TEXT,
                    grant_id TEXT,
                    session_id TEXT,
                    previous_hash TEXT,
                    event_hash TEXT
                )
            """)
            conn.commit()

    def record(self, request: ActionRequest, decision: Decision, grant_id: str | None) -> str:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            previous_hash = row[0] if row else "GENESIS"
            event_id = str(uuid.uuid4())
            timestamp = utc_now()
            payload = {
                "event_id": event_id,
                "timestamp": timestamp,
                "agent_id": request.agent_id,
                "action": request.action,
                "resource": request.resource,
                "purpose": request.purpose,
                "decision": "ALLOW" if decision.allowed else "DENY",
                "reason": decision.reason,
                "grant_id": grant_id,
                "session_id": request.session_id,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(
                (previous_hash + json.dumps(payload, sort_keys=True)).encode()
            ).hexdigest()
            conn.execute("""
                INSERT INTO audit_events
                (event_id,timestamp,agent_id,action,resource,purpose,decision,reason,
                 grant_id,session_id,previous_hash,event_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event_id, timestamp, request.agent_id, request.action, request.resource,
                request.purpose, payload["decision"], decision.reason, grant_id,
                request.session_id, previous_hash, event_hash
            ))
            conn.commit()
        return event_id

    def rows(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(
                "SELECT * FROM audit_events ORDER BY seq"
            ).fetchall()]

    def verify_chain(self) -> bool:
        previous = "GENESIS"
        for row in self.rows():
            payload = {
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "agent_id": row["agent_id"],
                "action": row["action"],
                "resource": row["resource"],
                "purpose": row["purpose"],
                "decision": row["decision"],
                "reason": row["reason"],
                "grant_id": row["grant_id"],
                "session_id": row["session_id"],
                "previous_hash": previous,
            }
            expected = hashlib.sha256(
                (previous + json.dumps(payload, sort_keys=True)).encode()
            ).hexdigest()
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                return False
            previous = row["event_hash"]
        return True
