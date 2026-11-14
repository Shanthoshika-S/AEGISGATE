from datetime import datetime, timedelta, timezone

from app.services.behavior_analyzer import BehaviorAnalyzer


def create_event(
    index,
    decision="ALLOW",
    tool_name="calculator",
    timestamp=None,
    agent_id="demo-agent",
):
    return {
        "event_id": f"event-{index}",
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool_name": tool_name,
        "operation": "test",
        "decision": decision,
        "executed": 1,
    }


def test_detects_excessive_activity():

    analyzer = BehaviorAnalyzer()

    events = [
        create_event(index)
        for index in range(10)
    ]

    result = analyzer.analyze(events)

    assert result["total_anomalies"] == 1
    assert result["anomalies"][0]["anomaly_type"] == "EXCESSIVE_ACTIVITY"
    assert result["anomalies"][0]["severity"] == "HIGH"


def test_detects_repeated_blocked_attempts():

    analyzer = BehaviorAnalyzer()

    events = [
        create_event(index, decision="BLOCK")
        for index in range(3)
    ]

    result = analyzer.analyze(events)

    assert result["total_anomalies"] == 1
    assert result["anomalies"][0]["anomaly_type"] == "REPEATED_BLOCKED_ATTEMPTS"


def test_detects_unusual_tool_diversity():

    analyzer = BehaviorAnalyzer()

    tools = [
        "calculator",
        "file_reader",
        "file_writer",
        "email_sender",
    ]

    events = [
        create_event(index, tool_name=tool)
        for index, tool in enumerate(tools)
    ]

    result = analyzer.analyze(events)

    assert result["total_anomalies"] == 1
    assert result["anomalies"][0]["anomaly_type"] == "UNUSUAL_TOOL_DIVERSITY"


def test_detects_repeated_sensitive_actions():

    analyzer = BehaviorAnalyzer()

    events = [
        create_event(index, decision="REQUIRE_APPROVAL")
        for index in range(3)
    ]

    result = analyzer.analyze(events)

    assert result["total_anomalies"] == 1
    assert result["anomalies"][0]["anomaly_type"] == "REPEATED_SENSITIVE_ACTIONS"


def test_ignores_events_outside_monitoring_window():

    analyzer = BehaviorAnalyzer()

    old_timestamp = (
        datetime.now(timezone.utc) - timedelta(minutes=2)
    ).isoformat()

    events = [
        create_event(index, timestamp=old_timestamp)
        for index in range(10)
    ]

    result = analyzer.analyze(events)

    assert result["events_analyzed"] == 0
    assert result["total_anomalies"] == 0
