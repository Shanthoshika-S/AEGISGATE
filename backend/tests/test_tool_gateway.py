
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_authorized_calculator_executes():
    response = client.post(
        "/tools/execute",
        json={
            "agent_id": "demo-agent",
            "tool_name": "calculator",
            "operation": "add",
            "parameters": {"a": 10, "b": 20},
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"]["action"] == "ALLOW"
    assert data["executed"] is True
    assert data["result"]["result"] == 30


def test_blocked_operation_never_executes():
    response = client.post(
        "/tools/execute",
        json={
            "agent_id": "demo-agent",
            "tool_name": "file_reader",
            "operation": "execute_shell",
            "parameters": {},
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"]["action"] == "BLOCK"
    assert data["executed"] is False
    assert data["result"] is None


def test_sensitive_operation_never_executes_without_approval():
    response = client.post(
        "/tools/execute",
        json={
            "agent_id": "demo-agent",
            "tool_name": "file_writer",
            "operation": "write",
            "parameters": {},
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"]["action"] == "REQUIRE_APPROVAL"
    assert data["executed"] is False
    assert data["result"] is None


def test_file_reader_returns_sample_file():
    response = client.post(
        "/tools/execute",
        json={
            "agent_id": "demo-agent",
            "tool_name": "file_reader",
            "operation": "read",
            "parameters": {"filename": "report.txt"},
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"]["action"] == "ALLOW"
    assert data["executed"] is True
    assert data["result"]["filename"] == "report.txt"
    assert data["result"]["content"] == (
        "AEGISGATE security test report."
    )
