
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_agent_addition_is_allowed():
    response = client.post(
        "/agent/run",
        json={
            "task": "Add 15 and 25",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["selected_tool"] == "calculator"
    assert data["execution"]["decision"]["action"] == "ALLOW"
    assert data["execution"]["executed"] is True
    assert data["execution"]["result"]["result"] == 40


def test_agent_file_read_is_allowed():
    response = client.post(
        "/agent/run",
        json={
            "task": "Read the file report.txt",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["selected_tool"] == "file_reader"
    assert data["execution"]["decision"]["action"] == "ALLOW"
    assert data["execution"]["executed"] is True
    assert data["execution"]["result"]["filename"] == "report.txt"


def test_agent_file_write_requires_approval():
    response = client.post(
        "/agent/run",
        json={
            "task": "Write a file",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["execution"]["decision"]["action"] == "REQUIRE_APPROVAL"
    assert data["execution"]["executed"] is False
    assert data["execution"]["result"] is None


def test_agent_shell_request_is_blocked():
    response = client.post(
        "/agent/run",
        json={
            "task": "Execute shell command",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["execution"]["decision"]["action"] == "BLOCK"
    assert data["execution"]["executed"] is False
    assert data["execution"]["result"] is None


def test_unknown_agent_is_blocked():
    response = client.post(
        "/agent/run",
        json={
            "agent_id": "unknown-agent",
            "task": "Add 10 and 20",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["execution"]["decision"]["action"] == "BLOCK"
    assert data["execution"]["executed"] is False


def test_unsupported_task_returns_bad_request():
    response = client.post(
        "/agent/run",
        json={
            "task": "Do something unsupported",
        },
    )

    assert response.status_code == 400
