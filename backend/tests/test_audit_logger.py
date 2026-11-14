import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from datetime import datetime, timezone

from app.models.security import (
    AgentToolRequest,
    SecurityAction,
    SecurityDecision,
)
from app.services.audit_logger import AuditLogger


def test_audit_event_is_saved_and_retrieved(tmp_path):

    database = tmp_path / "test_audit.db"
    logger = AuditLogger(db_path=database)

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="calculator",
        operation="add",
    )

    decision = SecurityDecision(
        action=SecurityAction.ALLOW,
        reason="Request complies with security policy.",
        request=request,
    )

    event_id = logger.log_event(
        request=request,
        decision=decision,
        executed=True,
    )

    events = logger.get_events()

    assert len(events) == 1
    assert events[0]["event_id"] == event_id
    assert events[0]["agent_id"] == "demo-agent"
    assert events[0]["decision"] == "ALLOW"
    assert events[0]["executed"] == 1


def test_blocked_event_is_recorded_as_not_executed(tmp_path):

    database = tmp_path / "test_blocked.db"
    logger = AuditLogger(db_path=database)

    request = AgentToolRequest(
        agent_id="unknown-agent",
        tool_name="file_reader",
        operation="read",
    )

    decision = SecurityDecision(
        action=SecurityAction.BLOCK,
        reason="Agent is not authorized.",
        request=request,
    )

    logger.log_event(
        request=request,
        decision=decision,
        executed=False,
    )

    events = logger.get_events()

    assert len(events) == 1
    assert events[0]["decision"] == "BLOCK"
    assert events[0]["executed"] == 0

def test_valid_hash_chain_passes_integrity_check(tmp_path):

    database = tmp_path / "test_chain.db"
    logger = AuditLogger(db_path=database)

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="calculator",
        operation="add",
    )

    decision = SecurityDecision(
        action=SecurityAction.ALLOW,
        reason="Request complies with security policy.",
        request=request,
    )

    logger.log_event(request, decision, True)
    logger.log_event(request, decision, True)

    result = logger.verify_integrity()

    assert result["valid"] is True
    assert result["checked_events"] == 2

    events = logger.get_events(limit=10)

    # get_events returns newest events first.
    newest_event = events[0]
    oldest_event = events[1]

    assert oldest_event["previous_hash"] == "GENESIS"
    assert newest_event["previous_hash"] == oldest_event["event_hash"]


def test_tampered_event_fails_integrity_check(tmp_path):

    database = tmp_path / "test_tampered.db"
    logger = AuditLogger(db_path=database)

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="calculator",
        operation="add",
    )

    decision = SecurityDecision(
        action=SecurityAction.ALLOW,
        reason="Request complies with security policy.",
        request=request,
    )

    event_id = logger.log_event(request, decision, True)

    # Simulate an attacker modifying a database record.
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE security_events
            SET reason = ?
            WHERE event_id = ?
            """,
            ("This record has been tampered with.", event_id),
        )

    result = logger.verify_integrity()

    assert result["valid"] is False
    assert result["failed_event_id"] == event_id
    assert result["reason"] == "Event data has been modified."

def test_legacy_events_are_reported_separately(tmp_path):

    database = tmp_path / "test_legacy.db"
    logger = AuditLogger(db_path=database)

    # Simulate an event created before hash chaining existed.
    with sqlite3.connect(database) as connection:
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
            "legacy-event-001",
            datetime.now(timezone.utc).isoformat(),
            "demo-agent",
            "calculator",
            "add",
            None,
            "ALLOW",
            "Legacy event without a hash.",
            1,
        ))

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="calculator",
        operation="add",
    )

    decision = SecurityDecision(
        action=SecurityAction.ALLOW,
        reason="Request complies with security policy.",
        request=request,
    )

    logger.log_event(request, decision, True)

    result = logger.verify_integrity()

    assert result["valid"] is True
    assert result["checked_events"] == 1
    assert result["legacy_events"] == 1
    assert result["legacy_events_verified"] is False

def test_concurrent_events_preserve_hash_chain(tmp_path):

    database = tmp_path / "test_concurrent.db"
    logger = AuditLogger(db_path=database)

    number_of_events = 8
    number_of_workers = 8

    barrier = Barrier(number_of_workers)

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="calculator",
        operation="add",
    )

    decision = SecurityDecision(
        action=SecurityAction.ALLOW,
        reason="Concurrent security test.",
        request=request,
    )

    def create_event():

        # Make all worker threads start logging together.
        barrier.wait()

        return logger.log_event(
            request=request,
            decision=decision,
            executed=True,
        )

    with ThreadPoolExecutor(max_workers=number_of_workers) as executor:

        futures = [
            executor.submit(create_event)
            for _ in range(number_of_events)
        ]

        event_ids = [
            future.result()
            for future in futures
        ]

    # Every event should have a unique ID.
    assert len(set(event_ids)) == number_of_events

    # Every event should have been saved.
    events = logger.get_events(limit=number_of_events)

    assert len(events) == number_of_events

    # The complete hash chain must remain valid.
    result = logger.verify_integrity()

    assert result["valid"] is True
    assert result["checked_events"] == number_of_events
    assert result["failed_event_id"] is None
