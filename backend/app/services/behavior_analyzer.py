from datetime import datetime, timedelta, timezone
from collections import defaultdict


class BehaviorAnalyzer:

    def __init__(
        self,
        activity_threshold=10,
        blocked_threshold=3,
        tool_diversity_threshold=4,
        sensitive_threshold=3,
        window_seconds=60,
    ):

        self.activity_threshold = activity_threshold
        self.blocked_threshold = blocked_threshold
        self.tool_diversity_threshold = tool_diversity_threshold
        self.sensitive_threshold = sensitive_threshold
        self.window_seconds = window_seconds

    @staticmethod
    def parse_timestamp(timestamp):

        parsed = datetime.fromisoformat(timestamp)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    def analyze(self, events):

        now = datetime.now(timezone.utc)

        cutoff = now - timedelta(
            seconds=self.window_seconds
        )

        recent_events = []

        for event in events:

            try:
                event_time = self.parse_timestamp(
                    event["timestamp"]
                )

            except (ValueError, TypeError, KeyError):
                continue

            if cutoff <= event_time <= now:
                recent_events.append(event)

        agent_events = defaultdict(list)

        for event in recent_events:
            agent_events[event["agent_id"]].append(event)

        anomalies = []

        for agent_id, events_for_agent in agent_events.items():

            event_ids = [
                event["event_id"]
                for event in events_for_agent
            ]

            # Rule 1: Excessive tool activity.
            activity_count = len(events_for_agent)

            if activity_count >= self.activity_threshold:

                anomalies.append({
                    "agent_id": agent_id,
                    "anomaly_type": "EXCESSIVE_ACTIVITY",
                    "severity": "HIGH",
                    "count": activity_count,
                    "threshold": self.activity_threshold,
                    "event_ids": event_ids,
                    "explanation": (
                        "The agent generated an unusually high "
                        "number of tool requests within the "
                        "monitoring window."
                    ),
                })

            # Rule 2: Repeated blocked operations.
            blocked_events = [
                event
                for event in events_for_agent
                if event["decision"] == "BLOCK"
            ]

            if len(blocked_events) >= self.blocked_threshold:

                anomalies.append({
                    "agent_id": agent_id,
                    "anomaly_type": "REPEATED_BLOCKED_ATTEMPTS",
                    "severity": "HIGH",
                    "count": len(blocked_events),
                    "threshold": self.blocked_threshold,
                    "event_ids": [
                        event["event_id"]
                        for event in blocked_events
                    ],
                    "explanation": (
                        "The agent repeatedly attempted operations "
                        "that were blocked by the security policy."
                    ),
                })

            # Rule 3: Unusual tool diversity.
            unique_tools = {
                event["tool_name"]
                for event in events_for_agent
            }

            if len(unique_tools) >= self.tool_diversity_threshold:

                anomalies.append({
                    "agent_id": agent_id,
                    "anomaly_type": "UNUSUAL_TOOL_DIVERSITY",
                    "severity": "MEDIUM",
                    "count": len(unique_tools),
                    "threshold": self.tool_diversity_threshold,
                    "tools": sorted(unique_tools),
                    "event_ids": event_ids,
                    "explanation": (
                        "The agent used an unusually large variety "
                        "of tools within the monitoring window."
                    ),
                })

            # Rule 4: Repeated sensitive operations.
            sensitive_events = [
                event
                for event in events_for_agent
                if event["decision"] == "REQUIRE_APPROVAL"
            ]

            if len(sensitive_events) >= self.sensitive_threshold:

                anomalies.append({
                    "agent_id": agent_id,
                    "anomaly_type": "REPEATED_SENSITIVE_ACTIONS",
                    "severity": "MEDIUM",
                    "count": len(sensitive_events),
                    "threshold": self.sensitive_threshold,
                    "event_ids": [
                        event["event_id"]
                        for event in sensitive_events
                    ],
                    "explanation": (
                        "The agent repeatedly requested operations "
                        "that require human approval."
                    ),
                })

        return {
            "monitoring_window_seconds": self.window_seconds,
            "events_analyzed": len(recent_events),
            "agents_analyzed": len(agent_events),
            "total_anomalies": len(anomalies),
            "anomalies": anomalies,
        }
