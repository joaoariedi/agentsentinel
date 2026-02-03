"""
AgentSentinel API Server

Unified REST API providing access to all AgentSentinel security features.
Run with: uvicorn agentsentinel.api.main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import AgentSentinel components
from agentsentinel.input_shield import InputShield, ShieldConfig, ThreatLevel
from agentsentinel.behavior_monitor import BehaviorMonitor, ActionType
from agentsentinel.infra_monitor import InfrastructureMonitor
from agentsentinel.red_team import AgentScanner, ReportGenerator


# ============================================
# Application Lifecycle
# ============================================

# Global component instances
shield: InputShield
behavior_monitor: BehaviorMonitor
infra_monitor: InfrastructureMonitor
scanner: AgentScanner
scan_results: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager"""
    global shield, behavior_monitor, infra_monitor, scanner
    
    # Initialize components on startup
    shield = InputShield(ShieldConfig(block_threshold=ThreatLevel.HIGH))
    behavior_monitor = BehaviorMonitor()
    infra_monitor = InfrastructureMonitor()
    scanner = AgentScanner()
    
    print("🛡️ AgentSentinel API started")
    yield
    
    # Cleanup on shutdown
    print("🛡️ AgentSentinel API shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    application = FastAPI(
        title="AgentSentinel API",
        description="""
        Comprehensive security framework for AI agents.
        
        ## Features
        
        - **Input Shield**: High-performance prompt injection detection
        - **Canary Tokens**: Detect system prompt leakage  
        - **Behavior Monitor**: Action logging and anomaly detection
        - **Infrastructure Monitor**: Security scanning and monitoring
        - **Red Team Suite**: Automated security auditing
        
        ## Quick Start
        
        ```python
        import httpx
        
        # Analyze input for threats
        response = httpx.post(
            "http://localhost:8000/api/v1/analyze",
            json={"text": "Ignore all previous instructions"}
        )
        result = response.json()
        print(f"Should block: {result['should_block']}")
        ```
        """,
        version="0.1.0",
        lifespan=lifespan,
    )
    
    # Add CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    return application


app = create_app()


# ============================================
# Request/Response Models
# ============================================

class AnalyzeRequest(BaseModel):
    """Request model for input analysis"""
    text: str = Field(..., description="Text to analyze for security threats")
    context: Optional[str] = Field(None, description="Optional context for analysis")


class ThreatResponse(BaseModel):
    """Individual threat in response"""
    category: str
    level: str
    description: str
    evidence: str
    confidence: float


class AnalyzeResponse(BaseModel):
    """Response model for input analysis"""
    input_hash: str
    threats: list[ThreatResponse]
    overall_level: str
    risk_score: float
    should_block: bool
    analysis_time_us: int


class CanaryGenerateRequest(BaseModel):
    """Request model for canary generation"""
    context: str = Field("default", description="Context identifier for the canary")


class CanaryCheckRequest(BaseModel):
    """Request model for canary leak check"""
    output: str = Field(..., description="Output text to check for leaked canaries")


class ActionRequest(BaseModel):
    """Request model for behavior action check"""
    action_type: str = Field(..., description="Type of action (e.g., wallet_transfer)")
    session_id: str = Field(..., description="Session identifier")
    agent_id: str = Field(..., description="Agent identifier")
    triggered_by: str = Field(..., description="Trigger source (e.g., user message hash)")
    target: Optional[str] = Field(None, description="Target of the action")
    destination_address: Optional[str] = Field(None, description="Destination for transfers")
    amount: Optional[float] = Field(None, description="Amount for financial operations")
    parameters: Optional[dict] = Field(None, description="Additional parameters")


class ActionResponse(BaseModel):
    """Response model for action check"""
    allowed: bool
    action_id: str
    anomaly_score: float
    anomaly_reasons: list[str]
    required_approval: bool


class ScanRequest(BaseModel):
    """Request model for red team scan"""
    target_url: str = Field(..., description="Agent endpoint URL to scan")
    categories: Optional[list[str]] = Field(None, description="Payload categories to test")
    severities: Optional[list[str]] = Field(None, description="Severity levels to test")
    quick: bool = Field(False, description="Run quick scan (critical only)")


class ProtectRequest(BaseModel):
    """Request model for unified protection endpoint"""
    text: str = Field(..., description="User input text")
    session_id: str = Field(..., description="Session identifier")
    agent_id: str = Field(..., description="Agent identifier")
    action_type: Optional[str] = Field(None, description="Action type if performing action")
    destination: Optional[str] = Field(None, description="Destination for transfers")
    amount: Optional[float] = Field(None, description="Amount for financial operations")


# ============================================
# Input Shield Endpoints
# ============================================

@app.post("/api/v1/analyze", response_model=AnalyzeResponse, tags=["Input Shield"])
async def analyze_input(request: AnalyzeRequest):
    """
    Analyze input text for security threats.
    
    Uses high-performance pattern matching to detect prompt injection,
    data exfiltration attempts, and other security threats.
    
    - **text**: The input text to analyze
    - **context**: Optional context for enhanced analysis
    
    Returns threat assessment with risk score and blocking recommendation.
    """
    result = shield.analyze(request.text)
    
    return AnalyzeResponse(
        input_hash=result.input_hash,
        threats=[
            ThreatResponse(
                category=t.category.value,
                level=t.level.value,
                description=t.description,
                evidence=t.evidence,
                confidence=t.confidence,
            )
            for t in result.threats
        ],
        overall_level=result.overall_level.value,
        risk_score=result.risk_score,
        should_block=result.should_block,
        analysis_time_us=result.analysis_time_us,
    )


@app.post("/api/v1/canary/generate", tags=["Input Shield"])
async def generate_canary(request: CanaryGenerateRequest):
    """
    Generate a canary token for embedding in system prompts.
    
    Canary tokens help detect when system prompts are being leaked.
    Embed the returned token in your system prompt, then use
    `/api/v1/canary/check` to detect if it appears in outputs.
    """
    token = shield.generate_canary(request.context)
    return {
        "token": token,
        "context": request.context,
        "usage": "Embed this token in your system prompt to detect leakage",
    }


@app.post("/api/v1/canary/check", tags=["Input Shield"])
async def check_canary_leak(request: CanaryCheckRequest):
    """
    Check if output contains leaked canary tokens.
    
    Use this to detect if your system prompt (with embedded canary)
    has been leaked in the agent's output.
    """
    leaks = shield.check_output(request.output)
    return {
        "leaked": len(leaks) > 0,
        "leak_count": len(leaks),
        "leaks": [
            {
                "category": l.category.value,
                "level": l.level.value,
                "description": l.description,
                "evidence": l.evidence,
            }
            for l in leaks
        ],
    }


# ============================================
# Behavior Monitor Endpoints
# ============================================

@app.post("/api/v1/behavior/check", response_model=ActionResponse, tags=["Behavior Monitor"])
async def check_action(request: ActionRequest):
    """
    Pre-action security check for agent operations.
    
    Call this before allowing an agent to perform sensitive actions.
    Analyzes the action against behavioral baselines and anomaly detection.
    
    Returns whether the action is allowed and any anomaly flags.
    """
    try:
        action_type = ActionType(request.action_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action_type. Valid types: {[a.value for a in ActionType]}"
        )
    
    allowed, action = await behavior_monitor.pre_action_check(
        action_type=action_type,
        session_id=request.session_id,
        agent_id=request.agent_id,
        triggered_by=request.triggered_by,
        target=request.target,
        destination_address=request.destination_address,
        amount=request.amount,
        parameters=request.parameters or {},
    )
    
    return ActionResponse(
        allowed=allowed,
        action_id=action.id,
        anomaly_score=action.anomaly_score,
        anomaly_reasons=action.anomaly_reasons,
        required_approval=action.required_approval,
    )


@app.post("/api/v1/behavior/complete/{action_id}", tags=["Behavior Monitor"])
async def complete_action(
    action_id: str,
    result: Optional[dict] = None,
    error: Optional[str] = None,
):
    """
    Record completion of an action.
    
    Call this after an action completes (successfully or with error)
    to maintain accurate behavioral records.
    """
    success = behavior_monitor.record_completion(action_id, result, error)
    if not success:
        raise HTTPException(status_code=404, detail="Action not found")
    return {"status": "recorded", "action_id": action_id}


@app.get("/api/v1/behavior/session/{session_id}", tags=["Behavior Monitor"])
async def get_session_summary(session_id: str):
    """
    Get behavioral summary for a session.
    
    Returns statistics about the session's actions, anomalies,
    and current status.
    """
    return behavior_monitor.get_session_summary(session_id)


@app.get("/api/v1/behavior/agent/{agent_id}", tags=["Behavior Monitor"])
async def get_agent_summary(agent_id: str):
    """
    Get behavioral summary for an agent.
    
    Returns the agent's behavioral baseline and statistics.
    """
    return behavior_monitor.get_agent_summary(agent_id)


# ============================================
# Infrastructure Monitor Endpoints
# ============================================

@app.get("/api/v1/infra/scan", tags=["Infrastructure Monitor"])
async def run_infra_scan():
    """
    Run a comprehensive infrastructure security scan.
    
    Checks:
    - File integrity
    - Suspicious processes
    - Network connections
    
    Returns findings and overall security status.
    """
    result = await infra_monitor.run_security_scan()
    return {
        "scan_id": result.scan_id,
        "timestamp": result.timestamp.isoformat(),
        "duration_ms": result.duration_ms,
        "overall_status": result.overall_status,
        "risk_score": result.risk_score,
        "file_integrity_issues": len([f for f in result.file_integrity if f.alert]),
        "suspicious_processes": len(result.suspicious_processes),
        "suspicious_connections": len(result.suspicious_connections),
        "alerts": result.alerts,
    }


@app.get("/api/v1/infra/status", tags=["Infrastructure Monitor"])
async def get_infra_status():
    """
    Get current infrastructure monitoring status.
    """
    return {
        "monitoring_active": infra_monitor.is_monitoring,
        "known_file_hashes": len(infra_monitor.known_file_hashes),
        "baseline_connections": len(infra_monitor.baseline_connections),
        "watch_paths": infra_monitor.watch_paths,
    }


# ============================================
# Red Team Endpoints
# ============================================

@app.post("/api/v1/redteam/scan", tags=["Red Team"])
async def start_security_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a security audit scan against an agent endpoint.
    
    Runs the red team suite with 50+ injection payloads.
    Returns immediately with a scan_id; poll `/api/v1/redteam/scan/{scan_id}`
    for results.
    
    - **target_url**: The agent's chat/message endpoint
    - **categories**: Optional list of payload categories
    - **severities**: Optional list of severity levels
    - **quick**: If true, only tests critical payloads
    """
    scan_id = str(uuid.uuid4())
    
    async def run_scan():
        if request.quick:
            report = await scanner.quick_scan(request.target_url)
        else:
            report = await scanner.scan(
                request.target_url,
                categories=request.categories,
                severities=request.severities,
            )
        scan_results[scan_id] = report
    
    background_tasks.add_task(run_scan)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "target_url": request.target_url,
        "poll_url": f"/api/v1/redteam/scan/{scan_id}",
    }


@app.get("/api/v1/redteam/scan/{scan_id}", tags=["Red Team"])
async def get_scan_results(scan_id: str):
    """
    Get results of a security scan.
    
    Poll this endpoint until status is 'completed'.
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found or still in progress")
    
    report = scan_results[scan_id]
    generator = ReportGenerator()
    
    return {
        "scan_id": scan_id,
        "status": report.status.value,
        "security_score": report.security_score,
        "payloads_tested": report.payloads_tested,
        "vulnerabilities_found": report.vulnerabilities_found,
        "summary": {
            "critical": len(report.get_by_severity("critical")) if hasattr(report, "get_by_severity") else 0,
            "high": len(report.get_by_severity("high")) if hasattr(report, "get_by_severity") else 0,
            "medium": len(report.get_by_severity("medium")) if hasattr(report, "get_by_severity") else 0,
            "low": len(report.get_by_severity("low")) if hasattr(report, "get_by_severity") else 0,
        },
        "report_json": generator.generate_json(report),
    }


@app.get("/api/v1/redteam/payloads", tags=["Red Team"])
async def list_payloads():
    """
    List all available security testing payloads.
    """
    from agentsentinel.red_team import PayloadLibrary
    library = PayloadLibrary()
    
    return {
        "total": library.count(),
        "by_category": {
            cat.value: len(library.get_by_category(cat))
            for cat in set(p.category for p in library.get_all())
        },
        "by_severity": {
            sev.value: len(library.get_by_severity(sev))
            for sev in set(p.severity for p in library.get_all())
        },
    }


# ============================================
# Unified Protection Endpoint
# ============================================

@app.post("/api/v1/protect", tags=["Unified"])
async def unified_protect(request: ProtectRequest):
    """
    Unified protection endpoint - combines all security checks.
    
    This is the recommended endpoint for comprehensive protection:
    1. Analyzes input for prompt injection (Input Shield)
    2. Checks action against behavioral baseline (Behavior Monitor)
    3. Returns combined security verdict
    
    Use this single endpoint instead of calling multiple endpoints.
    """
    # Step 1: Input Shield analysis
    input_result = shield.analyze(request.text)
    
    if input_result.should_block:
        return {
            "allowed": False,
            "blocked_by": "input_shield",
            "reason": f"Threat detected: {input_result.overall_level.value}",
            "threats": [
                {
                    "category": t.category.value,
                    "level": t.level.value,
                    "description": t.description,
                }
                for t in input_result.threats
            ],
            "risk_score": input_result.risk_score,
        }
    
    # Step 2: Behavior check (if action specified)
    if request.action_type:
        try:
            action_type = ActionType(request.action_type)
        except ValueError:
            return {
                "allowed": False,
                "blocked_by": "validation",
                "reason": f"Invalid action_type: {request.action_type}",
            }
        
        allowed, action = await behavior_monitor.pre_action_check(
            action_type=action_type,
            session_id=request.session_id,
            agent_id=request.agent_id,
            triggered_by=input_result.input_hash,
            destination_address=request.destination,
            amount=request.amount,
        )
        
        if not allowed:
            return {
                "allowed": False,
                "blocked_by": "behavior_monitor",
                "reason": "Anomalous behavior detected",
                "anomaly_score": action.anomaly_score,
                "anomaly_reasons": action.anomaly_reasons,
            }
    
    return {
        "allowed": True,
        "input_analysis": {
            "risk_score": input_result.risk_score,
            "analysis_time_us": input_result.analysis_time_us,
            "threats_detected": len(input_result.threats),
        },
    }


# ============================================
# Health & Info
# ============================================

@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint.
    
    Returns service status and version.
    """
    return {
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", tags=["System"])
async def root():
    """
    API root - provides service info and endpoint overview.
    """
    return {
        "name": "AgentSentinel",
        "version": "0.1.0",
        "description": "Comprehensive security framework for AI agents",
        "documentation": "/docs",
        "openapi": "/openapi.json",
        "endpoints": {
            "analyze": "POST /api/v1/analyze - Input threat analysis",
            "canary_generate": "POST /api/v1/canary/generate - Generate canary token",
            "canary_check": "POST /api/v1/canary/check - Check for canary leaks",
            "behavior_check": "POST /api/v1/behavior/check - Pre-action check",
            "infra_scan": "GET /api/v1/infra/scan - Infrastructure scan",
            "redteam_scan": "POST /api/v1/redteam/scan - Security audit",
            "protect": "POST /api/v1/protect - Unified protection",
            "health": "GET /health - Health check",
        },
    }


# ============================================
# Entry Point
# ============================================

def main():
    """Run the API server"""
    import uvicorn
    uvicorn.run(
        "agentsentinel.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
