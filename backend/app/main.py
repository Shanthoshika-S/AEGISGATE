
from fastapi import FastAPI
from datetime import datetime, timezone

app = FastAPI(
    title="AEGISGATE",
    description="Runtime Security Firewall and Digital Forensics Platform for AI Agents",
    version="0.1.0"
)


@app.get("/")
async def root():
    return {
        "project": "AEGISGATE",
        "message": "AI Agent Security Gateway is online",
        "version": "0.1.0"
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "AEGISGATE Security Gateway",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
