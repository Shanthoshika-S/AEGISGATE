
import hashlib
import json
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path

from app.models.security import AgentToolRequest, SecurityDecision


GENESIS_HASH = "GENESIS"


class AuditLogger:

    def __init__(self, db_path=None):

        default_path = (
            Path(__file__).resolve().parents[2]
            / "data"
            / "aegisgate.db"
        )

        self.db_path = Path(db_path) if db_path else default_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.initialize_database()

    def initialize_database(self):

        with sqlite3.connect(self.db_path) as connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    resource TEXT,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    executed INTEGER NOT NULL,
                    previous_hash TEXT,
                    event_hash TEXT
                )
            """)

            # Support databases created by the earlier version.
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(security_events)"
                ).fetchall()
            }

            if "previous_hash" not in columns:
                connection.execute(
                    "ALTER TABLE security_events ADD COLUMN previous_hash TEXT"
                )

            if "event_hash" not in columns:
                connection.execute(
                    "ALTER TABLE security_events ADD COLUMN event_hash TEXT"
                )

    @staticmethod
    def calculate_hash(event_data: dict) -> str:

        canonical_data = json.dumps(
            event_data,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            canonical_data.encode("utf-8")
        ).hexdigest()

    def log_event(
        self,
        request: AgentToolRequest,
        decision: SecurityDecision,
        executed: bool,
    ):

        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path, timeout=10) as connection:

            # Acquire the write lock before reading the previous hash.
            connection.execute("BEGIN IMMEDIATE")

            previous_event = connection.execute("""
                SELECT event_hash
                FROM security_events
                ORDER BY rowid DESC
                LIMIT 1
            """).fetchone()

            previous_hash = (
                previous_event[0]
                if previous_event and previous_event[0]
                else GENESIS_HASH
            )

            event_data = {
                "event_id": event_id,
                "timestamp": timestamp,
                "agent_id": request.agent_id,
                "tool_name": request.tool_name,
                "operation": request.operation,
                "resource": request.resource,
                "decision": decision.action.value,
                "reason": decision.reason,
                "executed": int(executed),
                "previous_hash": previous_hash,
            }

            event_hash = self.calculate_hash(event_data)

            connection.execute("""
                INSERT INTO security_events (
                    event_id,
                    timestamp,
                    agent_id,
                    tool_name,
                    operation,
                    resource,
                    decision,
                    reason,
                    executed,
                    previous_hash,
                    event_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                timestamp,
                request.agent_id,
                request.tool_name,
                request.operation,
                request.resource,
                decision.action.value,
                decision.reason,
                int(executed),
                previous_hash,
                event_hash,
            ))

        return event_id

    def get_events(self, limit: int = 100):

        limit = max(1, min(limit, 500))

        with sqlite3.connect(self.db_path) as connection:

            connection.row_factory = sqlite3.Row

            rows = connection.execute("""
                SELECT *
                FROM security_events
                ORDER BY rowid DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]


    def verify_integrity(self):

        with sqlite3.connect(self.db_path) as connection:

            connection.row_factory = sqlite3.Row

            events = connection.execute("""
                SELECT *
                FROM security_events
                ORDER BY rowid ASC
            """).fetchall()

        expected_previous_hash = GENESIS_HASH
        checked_events = 0
        legacy_events = 0
        chain_started = False

        for event in events:

            event = dict(event)

            # Identify records created before hash chaining existed.
            if not event["event_hash"] and not event["previous_hash"]:

                if chain_started:
                    return {
                        "valid": False,
                        "checked_events": checked_events,
                        "legacy_events": legacy_events,
                        "legacy_events_verified": False,
                        "failed_event_id": event["event_id"],
                        "reason": "Legacy event found inside the hash chain.",
                    }

                legacy_events += 1
                continue

            if not event["event_hash"] or not event["previous_hash"]:
                return {
                    "valid": False,
                    "checked_events": checked_events,
                    "legacy_events": legacy_events,
                    "legacy_events_verified": False,
                    "failed_event_id": event["event_id"],
                    "reason": "Incomplete integrity hash data.",
                }

            chain_started = True

            if event["previous_hash"] != expected_previous_hash:
                return {
                    "valid": False,
                    "checked_events": checked_events,
                    "legacy_events": legacy_events,
                    "legacy_events_verified": False,
                    "failed_event_id": event["event_id"],
                    "reason": "Previous hash does not match the chain.",
                }

            event_data = {
                key: event[key]
                for key in (
                    "event_id",
                    "timestamp",
                    "agent_id",
                    "tool_name",
                    "operation",
                    "resource",
                    "decision",
                    "reason",
                    "executed",
                    "previous_hash",
                )
            }

            calculated_hash = self.calculate_hash(event_data)

            if calculated_hash != event["event_hash"]:
                return {
                    "valid": False,
                    "checked_events": checked_events,
                    "legacy_events": legacy_events,
                    "legacy_events_verified": False,
                    "failed_event_id": event["event_id"],
                    "reason": "Event data has been modified.",
                }

            expected_previous_hash = event["event_hash"]
            checked_events += 1

        return {
            "valid": True,
            "checked_events": checked_events,
            "legacy_events": legacy_events,
            "legacy_events_verified": False,
            "failed_event_id": None,
            "reason": (
                "Hash chain verified. Legacy events are not "
                "covered by cryptographic integrity verification."
            ),
        }

