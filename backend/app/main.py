
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.models.security import (
    AgentTaskRequest,
    AgentToolRequest,
    SecurityAction,
    SecurityDecision,
    ToolExecutionRequest,
)
from app.services.agent_runner import AgentRunner
from app.services.policy_engine import PolicyEngine
from app.services.audit_logger import AuditLogger
from app.services.behavior_analyzer import BehaviorAnalyzer
from app.tools.simulator import ToolSimulator


app = FastAPI(
    title="AEGISGATE",
    description="Runtime Security Firewall and Digital Forensics Platform for AI Agents",
    version="0.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

policy_engine = PolicyEngine()
tool_simulator = ToolSimulator()
audit_logger = AuditLogger()
behavior_analyzer = BehaviorAnalyzer()
agent_runner = AgentRunner()


@app.get("/")
async def root():
    return {
        "project": "AEGISGATE",
        "message": "AI Agent Security Gateway is online",
        "version": "0.4.0",
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AEGISGATE Security Gateway",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/security/evaluate", response_model=SecurityDecision)
async def evaluate_security_request(request: AgentToolRequest):
    decision = policy_engine.evaluate(request)
    return decision


def process_tool_request(request: ToolExecutionRequest):

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


@app.post("/tools/execute")
async def execute_tool_request(request: ToolExecutionRequest):
    return process_tool_request(request)


@app.post("/agent/run")
async def run_agent_task(request: AgentTaskRequest):

    try:
        tool_request = agent_runner.create_tool_request(request)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    execution = process_tool_request(tool_request)

    return {
        "agent_id": request.agent_id,
        "task": request.task,
        "selected_tool": tool_request.tool_name,
        "selected_operation": tool_request.operation,
        "execution": execution,
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


@app.get("/security/anomalies")
async def get_security_anomalies():
    events = audit_logger.get_events(limit=500)
    anomaly_report = behavior_analyzer.analyze(events)
    return anomaly_report
