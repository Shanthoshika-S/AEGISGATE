
from enum import Enum
from pydantic import BaseModel, Field

class SecurityAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class AgentToolRequest(BaseModel):
    agent_id: str
    tool_name: str
    operation: str
    resource: str | None = None


class SecurityDecision(BaseModel):
    action: SecurityAction
    reason: str
    request: AgentToolRequest


class SecurityPolicy(BaseModel):
    allowed_agents: set[str] = {"demo-agent"}

    tool_permissions: dict[str, set[str]] = {
        "calculator": {"add", "subtract"},
        "file_reader": {"read"},
        "file_writer": {"write"},
        "email_sender": {"send"},
    }

    blocked_operations: set[str] = {
        "execute_shell",
        "delete_all",
    }

    approval_required_operations: set[str] = {
        "write",
        "send",
    }

class ToolExecutionRequest(AgentToolRequest):
    parameters: dict[str, str | int | float | bool] = Field(
        default_factory=dict
    )
