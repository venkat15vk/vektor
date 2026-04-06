"""
Vektor AI — FastAPI Application

REST API for:
- Signals: query, detail, execute, rollback
- Scans: trigger extraction + scoring
- Policies: Tier 2 CRUD, suggestions
- Features: per-identity feature vectors (future product surface)

All signal data is auth-gated. The public site sells the concept,
not the signal schema.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import structlog
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="Vektor AI",
    description="Identity intelligence for the agentic enterprise",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://getvektor.ai"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class SignalSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SignalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    DISMISSED = "dismissed"


class SignalResponse(BaseModel):
    signal_id: str
    model_id: str
    entity_name: str
    entity_type: str
    source: str
    confidence: float
    severity: SignalSeverity
    action: str
    blast_radius: dict[str, Any]
    rollback: str
    requires_human: bool
    explanation: str
    remediation_steps: list[dict[str, Any]]
    created_at: datetime
    status: SignalStatus


class SignalListResponse(BaseModel):
    signals: list[SignalResponse]
    total: int
    page: int
    page_size: int


class ExecuteRequest(BaseModel):
    approval_token: str = Field(description="Auth token proving human approved this action.")
    dry_run: bool = Field(default=False, description="If True, simulate without executing.")


class ExecuteResponse(BaseModel):
    signal_id: str
    execution_id: str
    status: str
    rollback_id: str | None = None
    steps_executed: list[dict[str, Any]]
    dry_run: bool


class RollbackResponse(BaseModel):
    rollback_id: str
    signal_id: str
    status: str
    steps_reversed: list[dict[str, Any]]


class ScanRequest(BaseModel):
    sources: list[str] = Field(
        default_factory=list,
        description="Source systems to scan. Empty = all connected.",
    )
    run_scoring: bool = Field(default=True, description="Run ML scoring after extraction.")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    sources: list[str]
    started_at: datetime


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    sources: list[str]
    started_at: datetime
    completed_at: datetime | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
    signals_generated: int = 0


class PolicyRequest(BaseModel):
    name: str
    description: str
    category: str
    scope: dict[str, Any] = Field(default_factory=dict)
    rules: list[dict[str, Any]] = Field(default_factory=list)
    action: str = "flag_for_review"
    severity: str = "medium"


class PolicyResponse(BaseModel):
    id: str
    customer_id: str
    name: str
    description: str
    category: str
    status: str
    action: str
    severity: str
    suggested_at: datetime
    approved_at: datetime | None = None
    cross_customer_approvals: int = 0
    performance: dict[str, Any] | None = None


class PolicySuggestionResponse(BaseModel):
    suggestions: list[dict[str, Any]]
    total: int


class FeatureVectorResponse(BaseModel):
    subject_id: str
    computed_at: datetime
    features: dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float


# ---------------------------------------------------------------------------
# In-memory state (replaced by real stores in production)
# ---------------------------------------------------------------------------

_signals: dict[str, dict[str, Any]] = {}
_scans: dict[str, dict[str, Any]] = {}
_executions: dict[str, dict[str, Any]] = {}
_rollbacks: dict[str, dict[str, Any]] = {}
_start_time = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health_check():
    """System health check."""
    uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
    return HealthResponse(status="healthy", version="0.1.0", uptime_seconds=uptime)


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

@app.get("/signals", response_model=SignalListResponse, tags=["signals"])
async def list_signals(
    severity: SignalSeverity | None = None,
    source: str | None = None,
    model_id: str | None = None,
    requires_human: bool | None = None,
    status: SignalStatus | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    """
    Query signals with filters.
    Returns paginated signal list sorted by severity then confidence.
    """
    filtered = list(_signals.values())

    if severity is not None:
        filtered = [s for s in filtered if s["severity"] == severity.value]
    if source is not None:
        filtered = [s for s in filtered if s["source"] == source]
    if model_id is not None:
        filtered = [s for s in filtered if s["model_id"] == model_id]
    if requires_human is not None:
        filtered = [s for s in filtered if s["requires_human"] == requires_human]
    if status is not None:
        filtered = [s for s in filtered if s["status"] == status.value]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    filtered.sort(key=lambda s: (severity_order.get(s["severity"], 4), -s["confidence"]))

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = filtered[start:end]

    return SignalListResponse(
        signals=[SignalResponse(**s) for s in page_items],
        total=total,
        page=page,
        page_size=page_size,
    )


@app.get("/signals/{signal_id}", response_model=SignalResponse, tags=["signals"])
async def get_signal(signal_id: str):
    """Get a single signal by ID."""
    signal = _signals.get(signal_id)
    if signal is None:
        raise HTTPException(status_code=404, detail=f"Signal {signal_id} not found")
    return SignalResponse(**signal)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

@app.post("/execute/{signal_id}", response_model=ExecuteResponse, tags=["execution"])
async def execute_remediation(signal_id: str, request: ExecuteRequest):
    """
    Execute remediation for a signal.
    Requires approval_token (human approval gate).
    Supports dry_run mode for previewing changes.
    """
    signal = _signals.get(signal_id)
    if signal is None:
        raise HTTPException(status_code=404, detail=f"Signal {signal_id} not found")

    if signal["status"] == "executed":
        raise HTTPException(status_code=409, detail="Signal already executed")

    if signal["requires_human"] and not request.approval_token:
        raise HTTPException(
            status_code=403,
            detail="This signal requires human approval. Provide approval_token.",
        )

    execution_id = str(uuid.uuid4())
    rollback_id = str(uuid.uuid4())

    steps_executed = []
    for step in signal.get("remediation_steps", []):
        step_result = {
            "step": step.get("description", "Unknown step"),
            "status": "simulated" if request.dry_run else "executed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        steps_executed.append(step_result)

    if not request.dry_run:
        signal["status"] = "executed"
        _rollbacks[rollback_id] = {
            "rollback_id": rollback_id,
            "signal_id": signal_id,
            "execution_id": execution_id,
            "rollback_payload": signal.get("remediation_steps", []),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    _executions[execution_id] = {
        "execution_id": execution_id,
        "signal_id": signal_id,
        "dry_run": request.dry_run,
        "steps": steps_executed,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "remediation_executed",
        signal_id=signal_id,
        execution_id=execution_id,
        dry_run=request.dry_run,
        steps=len(steps_executed),
    )

    return ExecuteResponse(
        signal_id=signal_id,
        execution_id=execution_id,
        status="simulated" if request.dry_run else "executed",
        rollback_id=rollback_id if not request.dry_run else None,
        steps_executed=steps_executed,
        dry_run=request.dry_run,
    )


@app.post("/rollback/{rollback_id}", response_model=RollbackResponse, tags=["execution"])
async def rollback_execution(rollback_id: str):
    """
    Reverse a previous remediation execution.
    Uses pre-computed rollback payloads for instant reversal.
    """
    rollback = _rollbacks.get(rollback_id)
    if rollback is None:
        raise HTTPException(status_code=404, detail=f"Rollback {rollback_id} not found")

    signal_id = rollback["signal_id"]
    signal = _signals.get(signal_id)
    if signal:
        signal["status"] = "rolled_back"

    steps_reversed = [
        {
            "step": f"Reversed: {step.get('description', 'Unknown')}",
            "status": "reversed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for step in rollback.get("rollback_payload", [])
    ]

    logger.info("rollback_executed", rollback_id=rollback_id, signal_id=signal_id)

    return RollbackResponse(
        rollback_id=rollback_id,
        signal_id=signal_id,
        status="rolled_back",
        steps_reversed=steps_reversed,
    )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

@app.post("/scan", response_model=ScanResponse, tags=["scan"])
async def trigger_scan(request: ScanRequest):
    """
    Trigger an extraction + scoring run.
    Connects to configured adapters, extracts identity data,
    computes features, and runs all models.
    """
    scan_id = str(uuid.uuid4())
    sources = request.sources or ["aws_iam", "okta", "entra", "netsuite"]

    scan = {
        "scan_id": scan_id,
        "status": "running",
        "sources": sources,
        "started_at": datetime.now(timezone.utc),
        "run_scoring": request.run_scoring,
    }
    _scans[scan_id] = scan

    logger.info("scan_triggered", scan_id=scan_id, sources=sources)

    # In production: dispatch async extraction tasks per source
    # For now, return immediately with scan_id for polling

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        sources=sources,
        started_at=scan["started_at"],
    )


@app.get("/scan/{scan_id}", response_model=ScanStatusResponse, tags=["scan"])
async def get_scan_status(scan_id: str):
    """Check the status of an extraction + scoring run."""
    scan = _scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return ScanStatusResponse(
        scan_id=scan["scan_id"],
        status=scan["status"],
        sources=scan["sources"],
        started_at=scan["started_at"],
        completed_at=scan.get("completed_at"),
        stats=scan.get("stats", {}),
        signals_generated=scan.get("signals_generated", 0),
    )


# ---------------------------------------------------------------------------
# Policies (Tier 2)
# ---------------------------------------------------------------------------

@app.get("/policies", response_model=list[PolicyResponse], tags=["policies"])
async def list_policies(
    status: str | None = None,
    category: str | None = None,
):
    """List customer policies (Tier 2)."""
    # Placeholder — in production, reads from PolicyEngine
    return []


@app.post("/policies", response_model=PolicyResponse, tags=["policies"])
async def create_policy(request: PolicyRequest):
    """Create or approve a new Tier 2 policy."""
    policy_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    return PolicyResponse(
        id=policy_id,
        customer_id="default",
        name=request.name,
        description=request.description,
        category=request.category,
        status="approved",
        action=request.action,
        severity=request.severity,
        suggested_at=now,
        approved_at=now,
    )


@app.get("/policies/suggestions", response_model=PolicySuggestionResponse, tags=["policies"])
async def get_policy_suggestions():
    """Get Tier 2 policy suggestions for the customer's environment."""
    # Placeholder — in production, reads from PolicySuggestionGenerator
    return PolicySuggestionResponse(suggestions=[], total=0)


# ---------------------------------------------------------------------------
# Features (future product surface)
# ---------------------------------------------------------------------------

@app.get("/features/{subject_id}", response_model=FeatureVectorResponse, tags=["features"])
async def get_feature_vector(subject_id: str):
    """
    Read-only API exposing feature vectors per identity.
    Customer security teams can build their own dashboards
    on Vektor's computed features.
    """
    # Placeholder — in production, reads from FeatureStore
    raise HTTPException(
        status_code=404,
        detail=f"Feature vector for {subject_id} not found",
    )
