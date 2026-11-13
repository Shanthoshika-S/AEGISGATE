
from app.models.security import (
    AgentToolRequest,
    SecurityAction,
    SecurityPolicy,
)
from app.services.policy_engine import PolicyEngine


def test_authorized_read_is_allowed():
    engine = PolicyEngine()

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="file_reader",
        operation="read",
        resource="report.txt",
    )

    decision = engine.evaluate(request)

    assert decision.action == SecurityAction.ALLOW


def test_unauthorized_agent_is_blocked():
    engine = PolicyEngine()

    request = AgentToolRequest(
        agent_id="unknown-agent",
        tool_name="file_reader",
        operation="read",
    )

    decision = engine.evaluate(request)

    assert decision.action == SecurityAction.BLOCK


def test_unauthorized_tool_is_blocked():
    engine = PolicyEngine()

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="database_admin",
        operation="query",
    )

    decision = engine.evaluate(request)

    assert decision.action == SecurityAction.BLOCK


def test_shell_execution_is_blocked():
    engine = PolicyEngine()

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="file_reader",
        operation="execute_shell",
    )

    decision = engine.evaluate(request)

    assert decision.action == SecurityAction.BLOCK


def test_file_write_requires_approval():
    engine = PolicyEngine()

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="file_writer",
        operation="write",
        resource="important.txt",
    )

    decision = engine.evaluate(request)

    assert decision.action == SecurityAction.REQUIRE_APPROVAL


def test_email_sending_requires_approval():
    engine = PolicyEngine()

    request = AgentToolRequest(
        agent_id="demo-agent",
        tool_name="email_sender",
        operation="send",
    )

    decision = engine.evaluate(request)

    assert decision.action == SecurityAction.REQUIRE_APPROVAL
