
import re

from app.models.security import AgentTaskRequest, ToolExecutionRequest


class AgentRunner:
    """
    Lightweight task-driven agent for demonstrating AEGISGATE.

    This is a deterministic tool-selection agent, not an LLM.
    All generated tool requests pass through the security gateway.
    """

    def create_tool_request(
        self,
        task_request: AgentTaskRequest,
    ) -> ToolExecutionRequest:

        task = task_request.task.strip()
        normalized = task.lower()

        # Detect potentially dangerous shell requests.
        if any(term in normalized for term in (
            "execute shell",
            "run shell",
            "run command",
            "execute command",
        )):
            return ToolExecutionRequest(
                agent_id=task_request.agent_id,
                tool_name="file_reader",
                operation="execute_shell",
                parameters={},
            )

        # Detect sensitive file-writing requests.
        if (
            "write" in normalized and "file" in normalized
        ) or (
            "create" in normalized and "file" in normalized
        ) or (
            "save" in normalized and "file" in normalized
        ):
            return ToolExecutionRequest(
                agent_id=task_request.agent_id,
                tool_name="file_writer",
                operation="write",
                resource="agent-created-file.txt",
                parameters={},
            )

        # Detect requests to read sample files.
        if "read" in normalized and "file" in normalized:
            match = re.search(
                r"\b[\w.-]+\.txt\b",
                task,
                re.IGNORECASE,
            )
            filename = match.group(0) if match else "report.txt"

            return ToolExecutionRequest(
                agent_id=task_request.agent_id,
                tool_name="file_reader",
                operation="read",
                resource=filename,
                parameters={"filename": filename},
            )

        # Detect simple addition requests.
        if "add" in normalized or "plus" in normalized:
            numbers = re.findall(
                r"(?<!\w)-?\d+(?:\.\d+)?",
                task,
            )

            if len(numbers) >= 2:
                a, b = float(numbers[0]), float(numbers[1])

                if a.is_integer():
                    a = int(a)
                if b.is_integer():
                    b = int(b)

                return ToolExecutionRequest(
                    agent_id=task_request.agent_id,
                    tool_name="calculator",
                    operation="add",
                    parameters={"a": a, "b": b},
                )

        raise ValueError(
            "The agent could not identify a supported task. "
            "Try addition, reading a sample file, writing a file, "
            "or requesting a shell command."
        )
