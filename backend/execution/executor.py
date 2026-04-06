"""
Vektor AI — Remediation Execution Engine

When a signal fires, AI agents execute remediation programmatically:
  1. Signal detected → structured remediation plan
  2. Human approval gate (if required)
  3. Agent executes via source system APIs
  4. Audit trail recorded
  5. Rollback payload available for instant reversal

This is NOT a chatbot. Agentic execution = programmatic, auditable, reversible.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class ExecutionStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    DRY_RUN = "dry_run"


class RemediationStep(BaseModel):
    """A single atomic step in a remediation plan."""
    order: int
    action: str                     # e.g., "revoke_policy", "disable_user", "remove_role"
    target_system: str              # e.g., "aws_iam", "okta", "entra", "netsuite"
    target_entity: str              # entity ID in the target system
    parameters: dict[str, Any] = Field(default_factory=dict)
    description: str                # human-readable description
    is_reversible: bool = True
    rollback_action: str | None = None    # action to reverse this step
    rollback_parameters: dict[str, Any] = Field(default_factory=dict)


class RemediationPlan(BaseModel):
    """Complete remediation plan for a signal."""
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    signal_id: str
    steps: list[RemediationStep]
    requires_human_approval: bool = True
    estimated_impact: str = ""
    rollback_type: str = "staged"   # staged | immediate | manual
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionRecord(BaseModel):
    """Audit record of an execution."""
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plan_id: str
    signal_id: str
    status: ExecutionStatus
    approved_by: str | None = None
    approved_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    steps_completed: list[dict[str, Any]] = Field(default_factory=list)
    steps_failed: list[dict[str, Any]] = Field(default_factory=list)
    rollback_id: str | None = None
    error: str | None = None


class Executor:
    """
    Remediation execution engine.

    Orchestrates the execution of remediation plans:
    1. Validate the plan and check approval
    2. Execute each step in order against the target system
    3. Record audit trail
    4. Generate rollback payload
    5. On failure: auto-rollback completed steps
    """

    def __init__(self) -> None:
        self._plans: dict[str, RemediationPlan] = {}
        self._executions: dict[str, ExecutionRecord] = {}
        self._audit_log: list[dict[str, Any]] = []

    def create_plan(self, signal: dict[str, Any]) -> RemediationPlan:
        """
        Generate a remediation plan from a signal.
        Maps signal action + entity to concrete remediation steps.
        """
        steps = self._map_signal_to_steps(signal)

        plan = RemediationPlan(
            signal_id=signal["signal_id"],
            steps=steps,
            requires_human_approval=signal.get("requires_human", True),
            estimated_impact=self._estimate_impact(signal, steps),
            rollback_type=signal.get("rollback", "staged"),
        )

        self._plans[plan.plan_id] = plan
        self._log_audit("plan_created", plan_id=plan.plan_id, signal_id=signal["signal_id"])

        logger.info(
            "remediation_plan_created",
            plan_id=plan.plan_id,
            signal_id=signal["signal_id"],
            steps=len(steps),
            requires_approval=plan.requires_human_approval,
        )

        return plan

    def approve(self, plan_id: str, approved_by: str) -> ExecutionRecord:
        """Approve a remediation plan for execution."""
        plan = self._plans.get(plan_id)
        if plan is None:
            raise ValueError(f"Plan {plan_id} not found")

        record = ExecutionRecord(
            plan_id=plan_id,
            signal_id=plan.signal_id,
            status=ExecutionStatus.APPROVED,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
        )
        self._executions[record.execution_id] = record
        self._log_audit(
            "plan_approved",
            plan_id=plan_id,
            execution_id=record.execution_id,
            approved_by=approved_by,
        )

        return record

    async def execute(
        self,
        execution_id: str,
        dry_run: bool = False,
    ) -> ExecutionRecord:
        """
        Execute a remediation plan.

        In dry_run mode, validates all steps without making changes.
        On failure, automatically rolls back completed steps.
        """
        record = self._executions.get(execution_id)
        if record is None:
            raise ValueError(f"Execution {execution_id} not found")

        plan = self._plans.get(record.plan_id)
        if plan is None:
            raise ValueError(f"Plan {record.plan_id} not found")

        if not dry_run and record.status != ExecutionStatus.APPROVED:
            raise ValueError(f"Execution must be approved before running, got {record.status}")

        record.status = ExecutionStatus.DRY_RUN if dry_run else ExecutionStatus.EXECUTING
        record.started_at = datetime.now(timezone.utc)

        completed_steps: list[dict[str, Any]] = []

        try:
            for step in plan.steps:
                step_result = await self._execute_step(step, dry_run=dry_run)
                completed_steps.append(step_result)
                record.steps_completed.append(step_result)

            record.status = ExecutionStatus.DRY_RUN if dry_run else ExecutionStatus.COMPLETED
            record.completed_at = datetime.now(timezone.utc)

            if not dry_run:
                # Generate rollback payload
                record.rollback_id = str(uuid.uuid4())

            self._log_audit(
                "execution_completed",
                execution_id=execution_id,
                dry_run=dry_run,
                steps_completed=len(completed_steps),
            )

            logger.info(
                "remediation_executed",
                execution_id=execution_id,
                status=record.status.value,
                steps_completed=len(completed_steps),
                dry_run=dry_run,
            )

        except Exception as exc:
            record.status = ExecutionStatus.FAILED
            record.error = str(exc)
            record.completed_at = datetime.now(timezone.utc)

            logger.error(
                "remediation_failed",
                execution_id=execution_id,
                error=str(exc),
                steps_completed=len(completed_steps),
            )

            # Auto-rollback completed steps on failure
            if not dry_run and completed_steps:
                await self._auto_rollback(plan, completed_steps, record)

        return record

    async def rollback(self, rollback_id: str) -> dict[str, Any]:
        """
        Reverse a previous execution using its rollback payload.
        Executes rollback actions in reverse order.
        """
        # Find the execution with this rollback_id
        record = None
        for exec_record in self._executions.values():
            if exec_record.rollback_id == rollback_id:
                record = exec_record
                break

        if record is None:
            raise ValueError(f"Rollback {rollback_id} not found")

        plan = self._plans.get(record.plan_id)
        if plan is None:
            raise ValueError(f"Plan {record.plan_id} not found")

        reversed_steps: list[dict[str, Any]] = []

        # Rollback in reverse order
        for step in reversed(plan.steps):
            if step.is_reversible and step.rollback_action:
                rollback_result = await self._execute_rollback_step(step)
                reversed_steps.append(rollback_result)

        record.status = ExecutionStatus.ROLLED_BACK

        self._log_audit(
            "rollback_completed",
            rollback_id=rollback_id,
            execution_id=record.execution_id,
            steps_reversed=len(reversed_steps),
        )

        logger.info(
            "rollback_executed",
            rollback_id=rollback_id,
            steps_reversed=len(reversed_steps),
        )

        return {
            "rollback_id": rollback_id,
            "execution_id": record.execution_id,
            "signal_id": record.signal_id,
            "status": "rolled_back",
            "steps_reversed": reversed_steps,
        }

    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        return self._executions.get(execution_id)

    def get_audit_log(self, signal_id: str | None = None) -> list[dict[str, Any]]:
        """Get audit log entries, optionally filtered by signal."""
        if signal_id:
            return [e for e in self._audit_log if e.get("signal_id") == signal_id]
        return list(self._audit_log)

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _map_signal_to_steps(self, signal: dict[str, Any]) -> list[RemediationStep]:
        """Map a signal's action to concrete remediation steps."""
        action = signal.get("action", "")
        source = signal.get("source", "")
        entity_id = signal.get("entity_id", "")

        steps: list[RemediationStep] = []

        if action == "revoke_permission":
            # Find the specific permission(s) to revoke from blast_radius
            blast = signal.get("blast_radius", {})
            permissions = blast.get("flagged_permissions", [signal.get("model_id", "unknown")])

            for i, perm in enumerate(permissions if isinstance(permissions, list) else [permissions]):
                steps.append(RemediationStep(
                    order=i + 1,
                    action="detach_policy",
                    target_system=source,
                    target_entity=entity_id,
                    parameters={"permission_id": perm},
                    description=f"Detach permission '{perm}' from entity {entity_id}",
                    is_reversible=True,
                    rollback_action="attach_policy",
                    rollback_parameters={"permission_id": perm},
                ))

        elif action == "disable_account":
            steps.append(RemediationStep(
                order=1,
                action="disable_account",
                target_system=source,
                target_entity=entity_id,
                parameters={},
                description=f"Disable account {entity_id} in {source}",
                is_reversible=True,
                rollback_action="enable_account",
                rollback_parameters={},
            ))

        elif action == "require_mfa":
            steps.append(RemediationStep(
                order=1,
                action="enforce_mfa",
                target_system=source,
                target_entity=entity_id,
                parameters={"mfa_type": "totp"},
                description=f"Enforce MFA on {entity_id} in {source}",
                is_reversible=True,
                rollback_action="remove_mfa_requirement",
                rollback_parameters={},
            ))

        elif action == "flag_for_review":
            steps.append(RemediationStep(
                order=1,
                action="create_review_ticket",
                target_system="vektor",
                target_entity=entity_id,
                parameters={
                    "signal_id": signal["signal_id"],
                    "priority": signal.get("severity", "medium"),
                },
                description=f"Create access review ticket for {entity_id}",
                is_reversible=False,
            ))

        else:
            # Generic step for unknown actions
            steps.append(RemediationStep(
                order=1,
                action=action,
                target_system=source,
                target_entity=entity_id,
                parameters=signal.get("remediation_steps", [{}])[0] if signal.get("remediation_steps") else {},
                description=f"Execute '{action}' on {entity_id} in {source}",
                is_reversible=False,
            ))

        return steps

    def _estimate_impact(self, signal: dict[str, Any], steps: list[RemediationStep]) -> str:
        """Estimate the impact of executing the remediation plan."""
        blast = signal.get("blast_radius", {})
        total_reach = blast.get("total_reach", 0)
        critical = len(blast.get("critical_resources", []))

        parts = [f"{len(steps)} remediation step(s)"]
        if total_reach:
            parts.append(f"affects {total_reach} resources")
        if critical:
            parts.append(f"including {critical} critical")

        return ", ".join(parts)

    async def _execute_step(self, step: RemediationStep, dry_run: bool = False) -> dict[str, Any]:
        """
        Execute a single remediation step against the target system.
        In production, this dispatches to the appropriate adapter's write API.
        """
        result = {
            "order": step.order,
            "action": step.action,
            "target_system": step.target_system,
            "target_entity": step.target_entity,
            "description": step.description,
            "status": "simulated" if dry_run else "executed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if not dry_run:
            # In production: dispatch to adapter
            # await adapter.execute_action(step.action, step.target_entity, step.parameters)
            logger.info(
                "step_executed",
                action=step.action,
                target=step.target_entity,
                system=step.target_system,
            )

        return result

    async def _execute_rollback_step(self, step: RemediationStep) -> dict[str, Any]:
        """Execute the rollback action for a step."""
        result = {
            "original_action": step.action,
            "rollback_action": step.rollback_action,
            "target_system": step.target_system,
            "target_entity": step.target_entity,
            "status": "reversed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # In production: dispatch to adapter
        # await adapter.execute_action(step.rollback_action, step.target_entity, step.rollback_parameters)
        logger.info(
            "step_rolled_back",
            original_action=step.action,
            rollback_action=step.rollback_action,
            target=step.target_entity,
        )

        return result

    async def _auto_rollback(
        self,
        plan: RemediationPlan,
        completed_steps: list[dict[str, Any]],
        record: ExecutionRecord,
    ) -> None:
        """Auto-rollback completed steps on execution failure."""
        logger.warning(
            "auto_rollback_triggered",
            execution_id=record.execution_id,
            steps_to_reverse=len(completed_steps),
        )

        completed_orders = {s["order"] for s in completed_steps}
        for step in reversed(plan.steps):
            if step.order in completed_orders and step.is_reversible and step.rollback_action:
                await self._execute_rollback_step(step)

    def _log_audit(self, event: str, **kwargs: Any) -> None:
        """Append to the audit log."""
        entry = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        self._audit_log.append(entry)
