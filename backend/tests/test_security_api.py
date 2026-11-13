from fastapi.testclient import TestClient

from app.main import app
from app.models.security import (
    AgentToolRequest,
    SecurityAction,
    SecurityDecision,
)
from app.services.audit_logger import AuditLogger


def test_security_verify_endpoint(tmp_path, monkeypatch):

    test_logger = AuditLogger(
        db_path=tmp_path / "test_audit.db"
    )

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="calculator",
        operation="add",
    )

    decision = SecurityDecision(
        action=SecurityAction.ALLOW,
        reason="Operation permitted.",
        request=request,
    )

    test_logger.log_event(
        request=request,
        decision=decision,
        executed=True,
    )

    monkeypatch.setattr(
        "app.main.audit_logger",
        test_logger,
    )

    client = TestClient(app)

    response = client.get("/security/verify")

    assert response.status_code == 200

    report = response.json()

    assert report["valid"] is True
    assert report["checked_events"] == 1
    assert report["legacy_events"] == 0
    assert report["failed_event_id"] is None
