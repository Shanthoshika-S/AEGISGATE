
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path

from app.models.security import AgentToolRequest, SecurityDecision


class AuditLogger:

    def __init__(self, db_path=None):

        # Store the database inside backend/data/.
        default_path = (
            Path(__file__).resolve().parents[2]
            / "data"
            / "aegisgate.db"
        )

        self.db_path = Path(db_path) if db_path else default_path

        # Create the data directory if it does not exist.
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
                    executed INTEGER NOT NULL
                )
            """)

    def log_event(
        self,
        request: AgentToolRequest,
        decision: SecurityDecision,
        executed: bool,
    ):

        event_id = str(uuid.uuid4())

        timestamp = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as connection:

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
                    executed
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ))

        return event_id

    def get_events(self, limit: int = 100):

        # Restrict the number of records returned.
        limit = max(1, min(limit, 500))

        with sqlite3.connect(self.db_path) as connection:

            connection.row_factory = sqlite3.Row

            rows = connection.execute("""
                SELECT *
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]

