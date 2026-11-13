
from app.models.security import (
    AgentToolRequest,
    SecurityAction,
    SecurityDecision,
    SecurityPolicy,
)


class PolicyEngine:
    def __init__(self, policy: SecurityPolicy | None = None):
        self.policy = policy or SecurityPolicy()

    def evaluate(self, request: AgentToolRequest) -> SecurityDecision:

        # 1. Check whether the agent is trusted.
        if request.agent_id not in self.policy.allowed_agents:
            return SecurityDecision(
                action=SecurityAction.BLOCK,
                reason="Agent is not authorized.",
                request=request,
            )

        # 2. Check whether the requested tool exists in the policy.
        if request.tool_name not in self.policy.tool_permissions:
            return SecurityDecision(
                action=SecurityAction.BLOCK,
                reason="Tool is not authorized.",
                request=request,
            )

        # 3. Check whether the requested operation is explicitly blocked.
        if request.operation in self.policy.blocked_operations:
            return SecurityDecision(
                action=SecurityAction.BLOCK,
                reason="Operation is explicitly blocked by security policy.",
                request=request,
            )

        # 4. Check whether this tool is permitted to perform this operation.
        permitted_operations = self.policy.tool_permissions[request.tool_name]

        if request.operation not in permitted_operations:
            return SecurityDecision(
                action=SecurityAction.BLOCK,
                reason="Operation is not permitted for this tool.",
                request=request,
            )

        # 5. Require human approval for sensitive operations.
        if request.operation in self.policy.approval_required_operations:
            return SecurityDecision(
                action=SecurityAction.REQUIRE_APPROVAL,
                reason="Operation requires human approval.",
                request=request,
            )

        # 6. Otherwise, allow the operation.
        return SecurityDecision(
            action=SecurityAction.ALLOW,
            reason="Request complies with security policy.",
            request=request,
        )
