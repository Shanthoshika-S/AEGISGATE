
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
