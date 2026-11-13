
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query

from app.models.security import (
    AgentToolRequest,
    SecurityAction,
    SecurityDecision,
    ToolExecutionRequest,
)
from app.services.policy_engine import PolicyEngine
from app.services.audit_logger import AuditLogger
from app.tools.simulator import ToolSimulator


app = FastAPI(
    title="AEGISGATE",
    description="Runtime Security Firewall and Digital Forensics Platform for AI Agents",
    version="0.4.0"
)

# Initialize security components.
policy_engine = PolicyEngine()
tool_simulator = ToolSimulator()
audit_logger = AuditLogger()


@app.get("/")
async def root():
    return {
        "project": "AEGISGATE",
        "message": "AI Agent Security Gateway is online",
        "version": "0.4.0"
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AEGISGATE Security Gateway",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/security/evaluate", response_model=SecurityDecision)
async def evaluate_security_request(request: AgentToolRequest):
    decision = policy_engine.evaluate(request)
    return decision


@app.post("/tools/execute")
async def execute_tool_request(request: ToolExecutionRequest):

    # Step 1: Evaluate the requested action.
    decision = policy_engine.evaluate(request)

    # Step 2: Stop blocked and approval-required actions.
    if decision.action != SecurityAction.ALLOW:

        event_id = audit_logger.log_event(
            request=request,
            decision=decision,
            executed=False,
        )

        return {
            "event_id": event_id,
            "decision": decision,
            "executed": False,
            "result": None,
        }

    # Step 3: Execute only authorized operations.
    try:
        result = tool_simulator.execute(
            tool_name=request.tool_name,
            operation=request.operation,
            parameters=request.parameters,
        )

    except ValueError as error:

        # Record the failed execution attempt.
        event_id = audit_logger.log_event(
            request=request,
            decision=decision,
            executed=False,
        )

        raise HTTPException(
            status_code=400,
            detail={
                "message": str(error),
                "event_id": event_id,
            },
        )

    # Step 4: Record successful execution.
    event_id = audit_logger.log_event(
        request=request,
        decision=decision,
        executed=True,
    )

    return {
        "event_id": event_id,
        "decision": decision,
        "executed": True,
        "result": result,
    }


@app.get("/security/events")
async def get_security_events(
    limit: int = Query(default=100, ge=1, le=500),
):
    events = audit_logger.get_events(limit=limit)

    return {
        "total": len(events),
        "events": events,
    }
@app.get("/security/verify")
async def verify_security_integrity():

    integrity_report = audit_logger.verify_integrity()

    return integrity_report
