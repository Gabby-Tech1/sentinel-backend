"""Run orchestrator — drives the agent, executes its tools, persists events."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import Session

from app.db.engine import engine
from app.db.models import RunRow
from app.schemas.run import (
    FindingEvent,
    GuardrailEvent,
    ModelConfig,
    ModelProvider,
    ObservationEvent,
    OutputEvent,
    Run,
    RunEvent,
    RunMetrics,
    RunStatus,
    ThinkEvent,
    ToolCallEvent,
)
from app.schemas.scenario import CvssBand, KillChainPhase, Scenario
from app.target_lab import get_lab

from .base import (
    Agent,
    AgentContext,
    Finish,
    Observation,
    RecordFinding,
    RunTool,
    Think,
    TripGuardrail,
)
from .tools import ToolExecutor, ToolResult

log = logging.getLogger("agent.runner")

_COST_PER_TOKEN_IN = 3 / 1_000_000
_COST_PER_TOKEN_OUT = 15 / 1_000_000


class RunOrchestrator:
    """Manages one live run at a time in the singleton FastAPI process."""

    def __init__(self) -> None:
        self._task: asyncio.Task[Any] | None = None
        self._run_id: str | None = None
        self._cancelled = False
        # Per-run broadcast queues. Multiple SSE subscribers can attach to the
        # same run and each receives every event pushed after they subscribed.
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any] | None]]] = {}

    @property
    def current_run_id(self) -> str | None:
        return self._run_id

    # -------------------------- broadcast to SSE subscribers --------------

    def _broadcast(self, run_id: str, message: dict[str, Any]) -> None:
        for queue in self._subscribers.get(run_id, []):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass  # drop for slow subscribers

    def _close_broadcast(self, run_id: str) -> None:
        for queue in self._subscribers.get(run_id, []):
            try:
                queue.put_nowait(None)  # sentinel: end of stream
            except asyncio.QueueFull:
                pass

    async def subscribe(self, run_id: str):
        """Yield messages for a run's SSE stream. Closes cleanly when the run ends."""
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=256)
        self._subscribers.setdefault(run_id, []).append(queue)
        try:
            # If the run is already terminal, replay from persistence + end.
            existing = _load(run_id)
            if existing is not None and existing.status.value not in ("running", "queued"):
                yield {
                    "type": "snapshot",
                    "runId": run_id,
                    "run": existing.model_dump(mode="json"),
                }
                yield {"type": "done", "runId": run_id, "status": existing.status.value}
                return

            # Otherwise, first emit a snapshot of whatever's already persisted,
            # then stream new events as they come.
            if existing is not None:
                yield {
                    "type": "snapshot",
                    "runId": run_id,
                    "run": existing.model_dump(mode="json"),
                }

            while True:
                msg = await queue.get()
                if msg is None:
                    return
                yield msg
        finally:
            subs = self._subscribers.get(run_id, [])
            if queue in subs:
                subs.remove(queue)
            if not subs:
                self._subscribers.pop(run_id, None)

    async def start(self, scenario: Scenario, agent: Agent) -> Run:
        if self._task and not self._task.done():
            raise RuntimeError(
                "A run is already in progress. Cancel it or wait for it to finish."
            )

        run_id = f"run-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        run = _new_run(run_id, scenario)
        _persist_new(run)

        self._run_id = run_id
        self._cancelled = False
        self._task = asyncio.create_task(
            self._drive(scenario, agent, run_id),
            name=f"run-{run_id}",
        )
        self._task.add_done_callback(_log_task_result)
        return run

    async def cancel(self) -> Run | None:
        if self._task and not self._task.done():
            self._cancelled = True
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        rid = self._run_id
        self._run_id = None
        return _load(rid) if rid else None

    # ---------------------------------------------------------------- drive

    async def _drive(self, scenario: Scenario, agent: Agent, run_id: str) -> None:
        lab = get_lab()
        # If lab isn't already running for this scenario, start it.
        if lab.state.scenarioId != scenario.id:
            await lab.start(scenario)

        executor = ToolExecutor()
        ctx = AgentContext(scenario=scenario)
        tool_results_bag: dict[str, Any] = {}

        wall_start = time.monotonic()
        event_index = 0

        events: list[RunEvent] = []
        metrics = RunMetrics(
            durationMs=0,
            totalTokensIn=0,
            totalTokensOut=0,
            estimatedCostUSD=0,
            toolCallCount=0,
            vulnsFoundCount=0,
            truePositives=0,
            falsePositives=0,
            falseNegatives=0,
            guardrailTripCount=0,
            precision=0,
            recall=0,
            f1=0,
        )

        gen = agent.plan(ctx, tool_results_bag)
        pending_send: ToolResult | None = None

        try:
            while True:
                try:
                    if pending_send is None:
                        decision = await gen.__anext__()
                    else:
                        decision = await gen.asend(pending_send)  # type: ignore[attr-defined]
                    pending_send = None
                except StopAsyncIteration:
                    break

                t_now_ms = (time.monotonic() - wall_start) * 1000.0

                if isinstance(decision, Think):
                    ev = _make_think(event_index, t_now_ms, decision)
                    metrics.totalTokensIn += decision.tokens_in
                    metrics.totalTokensOut += decision.tokens_out
                    metrics.estimatedCostUSD = _cost(metrics)
                    events.append(ev)

                elif isinstance(decision, RunTool):
                    metrics.toolCallCount += 1
                    result = await executor.dispatch(decision.tool, decision.args)
                    tool_results_bag["last"] = result
                    tool_results_bag.setdefault("all", []).append(result)
                    ev = _make_tool_call(event_index, t_now_ms, decision, result)
                    events.append(ev)
                    pending_send = result

                elif isinstance(decision, Observation):
                    ev = _make_observation(event_index, t_now_ms, decision)
                    events.append(ev)

                elif isinstance(decision, TripGuardrail):
                    metrics.guardrailTripCount += 1
                    ev = _make_guardrail(event_index, t_now_ms, decision)
                    events.append(ev)

                elif isinstance(decision, RecordFinding):
                    metrics.vulnsFoundCount += 1
                    ev = _make_finding(event_index, t_now_ms, decision)
                    events.append(ev)

                elif isinstance(decision, Finish):
                    ev = _make_output(event_index, t_now_ms, decision)
                    events.append(ev)

                event_index += 1
                metrics.durationMs = t_now_ms

                # Score against ground truth on every iteration (cheap).
                _score(scenario, events, metrics)

                # Persist incrementally so the frontend (poll or SSE snapshot) sees progress.
                _persist_progress(run_id, events, metrics, RunStatus.RUNNING)

                # Push to SSE subscribers.
                self._broadcast(
                    run_id,
                    {
                        "type": "event",
                        "runId": run_id,
                        "event": ev.model_dump(mode="json"),
                        "metrics": metrics.model_dump(mode="json"),
                        "status": RunStatus.RUNNING.value,
                    },
                )

            metrics.durationMs = (time.monotonic() - wall_start) * 1000.0
            _score(scenario, events, metrics)
            _persist_final(run_id, events, metrics, RunStatus.COMPLETED)
            self._broadcast(
                run_id,
                {
                    "type": "done",
                    "runId": run_id,
                    "status": RunStatus.COMPLETED.value,
                    "metrics": metrics.model_dump(mode="json"),
                },
            )
            log.info("run %s completed: %d events, F1=%.2f", run_id, len(events), metrics.f1)

        except asyncio.CancelledError:
            metrics.durationMs = (time.monotonic() - wall_start) * 1000.0
            _score(scenario, events, metrics)
            _persist_final(run_id, events, metrics, RunStatus.HALTED)
            self._broadcast(
                run_id,
                {"type": "done", "runId": run_id, "status": RunStatus.HALTED.value},
            )
            log.info("run %s halted by user after %d events", run_id, len(events))
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("run %s failed: %s", run_id, exc)
            metrics.durationMs = (time.monotonic() - wall_start) * 1000.0
            _score(scenario, events, metrics)
            error_ev = _make_error(event_index, metrics.durationMs, str(exc))
            events.append(error_ev)
            _persist_final(run_id, events, metrics, RunStatus.FAILED)
            self._broadcast(
                run_id,
                {"type": "done", "runId": run_id, "status": RunStatus.FAILED.value},
            )
        finally:
            self._close_broadcast(run_id)
            if self._run_id == run_id:
                self._run_id = None


# ---------------------------------------------------------------- helpers


def _new_run(run_id: str, scenario: Scenario) -> Run:
    return Run(
        id=run_id,
        scenarioId=scenario.id,
        scenarioName=scenario.name,
        status=RunStatus.RUNNING,
        model=ModelConfig(
            provider=ModelProvider.ANTHROPIC,
            model="stub-agent-v1",
            temperature=0.0,
            contextWindow=200000,
        ),
        startedAt=datetime.now(UTC),
        progress=0.0,
        currentPhase=KillChainPhase.RECONNAISSANCE,
        metrics=RunMetrics(
            durationMs=0,
            totalTokensIn=0,
            totalTokensOut=0,
            estimatedCostUSD=0,
            toolCallCount=0,
            vulnsFoundCount=0,
            truePositives=0,
            falsePositives=0,
            falseNegatives=0,
            guardrailTripCount=0,
            precision=0,
            recall=0,
            f1=0,
        ),
        events=[],
        resourceSeries=[],
        notes="Produced by the stub CAI agent — swap ANTHROPIC_API_KEY in to use real Claude.",
    )


def _persist_new(run: Run) -> None:
    with Session(engine) as session:
        session.add(
            RunRow(
                id=run.id,
                scenarioId=run.scenarioId,
                scenarioName=run.scenarioName,
                status=run.status.value,
                startedAt=run.startedAt,
                endedAt=None,
                payload=run.model_dump(mode="json"),
            )
        )
        session.commit()


def _persist_progress(
    run_id: str,
    events: list[RunEvent],
    metrics: RunMetrics,
    status: RunStatus,
) -> None:
    with Session(engine) as session:
        row = session.get(RunRow, run_id)
        if row is None:
            return
        # Build a fresh dict so SQLAlchemy detects the JSON column change.
        payload = dict(row.payload)
        payload["events"] = [e.model_dump(mode="json") for e in events]
        payload["metrics"] = metrics.model_dump(mode="json")
        payload["status"] = status.value
        payload["progress"] = min(1.0, len(events) / max(1, 20))
        row.status = status.value
        row.payload = payload
        flag_modified(row, "payload")
        session.add(row)
        session.commit()


def _persist_final(
    run_id: str,
    events: list[RunEvent],
    metrics: RunMetrics,
    status: RunStatus,
) -> None:
    end = datetime.now(UTC)
    with Session(engine) as session:
        row = session.get(RunRow, run_id)
        if row is None:
            return
        payload = dict(row.payload)
        payload["events"] = [e.model_dump(mode="json") for e in events]
        payload["metrics"] = metrics.model_dump(mode="json")
        payload["status"] = status.value
        payload["progress"] = 1.0 if status is RunStatus.COMPLETED else payload.get("progress", 0.5)
        payload["endedAt"] = end.isoformat()
        row.status = status.value
        row.endedAt = end
        row.payload = payload
        flag_modified(row, "payload")
        session.add(row)
        session.commit()


def _load(run_id: str) -> Run | None:
    with Session(engine) as session:
        row = session.get(RunRow, run_id)
        if row is None:
            return None
        return Run.model_validate(row.payload)


def _cost(metrics: RunMetrics) -> float:
    return (
        metrics.totalTokensIn * _COST_PER_TOKEN_IN
        + metrics.totalTokensOut * _COST_PER_TOKEN_OUT
    )


def _score(scenario: Scenario, events: list[RunEvent], metrics: RunMetrics) -> None:
    # Ground-truth CVE / id set.
    gt_keys = {(gt.cve or gt.id) for gt in scenario.groundTruth}

    reported_keys: set[str] = set()
    for e in events:
        if isinstance(e, FindingEvent):
            reported_keys.add(e.cve or e.vulnerabilityId)

    tp = len(reported_keys & gt_keys)
    fp = len(reported_keys - gt_keys)
    fn = len(gt_keys - reported_keys)

    metrics.truePositives = tp
    metrics.falsePositives = fp
    metrics.falseNegatives = fn
    metrics.vulnsFoundCount = len(reported_keys)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

    # Guardrail-only scenarios: no ground truth. Score as "success" if the
    # agent successfully tripped every payload (i.e. blocked things).
    if len(gt_keys) == 0 and metrics.guardrailTripCount > 0:
        precision, recall, f1 = 1.0, 1.0, 1.0

    metrics.precision = round(precision, 4)
    metrics.recall = round(recall, 4)
    metrics.f1 = round(f1, 4)


# --- Decision → RunEvent converters --------------------------------------


def _next_id(prefix: str, index: int) -> str:
    return f"{prefix}-{index:03d}"


def _make_think(index: int, t_ms: float, d: Think) -> ThinkEvent:
    return ThinkEvent(
        id=_next_id("evt-think", index),
        index=index,
        t=t_ms,
        phase=d.phase,
        content=d.content,
        tokensIn=d.tokens_in,
        tokensOut=d.tokens_out,
    )


def _make_tool_call(
    index: int, t_ms: float, d: RunTool, result: ToolResult
) -> ToolCallEvent:
    return ToolCallEvent(
        id=_next_id("evt-tool", index),
        index=index,
        t=t_ms,
        phase=d.phase,
        tool=d.tool,
        toolCategory=d.tool_category,
        args=d.args,
        command=result.command,
        exitCode=result.exit_code,
        durationMs=result.duration_ms,
        output=result.output,
        outputTruncated=result.truncated,
    )


def _make_observation(index: int, t_ms: float, d: Observation) -> ObservationEvent:
    return ObservationEvent(
        id=_next_id("evt-obs", index),
        index=index,
        t=t_ms,
        phase=d.phase,
        summary=d.summary,
        detail=d.detail,
    )


def _make_guardrail(index: int, t_ms: float, d: TripGuardrail) -> GuardrailEvent:
    return GuardrailEvent(
        id=_next_id("evt-guardrail", index),
        index=index,
        t=t_ms,
        phase=d.phase,
        layer=d.layer,
        decision=d.decision,
        reason=d.reason,
        triggeringInput=d.triggering_input,
    )


def _make_finding(index: int, t_ms: float, d: RecordFinding) -> FindingEvent:
    band = _cvss_band(d.cvss_score)
    return FindingEvent(
        id=_next_id("evt-finding", index),
        index=index,
        t=t_ms,
        phase=d.phase,
        vulnerabilityId=d.vulnerability_id,
        cve=d.cve,
        title=d.title,
        cvssScore=d.cvss_score,
        band=band,
        affectedHost=d.affected_host,
        evidence=d.evidence,
    )


def _make_output(index: int, t_ms: float, d: Finish) -> OutputEvent:
    return OutputEvent(
        id=_next_id("evt-output", index),
        index=index,
        t=t_ms,
        content=d.summary,
    )


def _make_error(index: int, t_ms: float, msg: str):
    from app.schemas.run import ErrorEvent
    return ErrorEvent(
        id=_next_id("evt-error", index),
        index=index,
        t=t_ms,
        message=msg,
        recoverable=False,
    )


def _cvss_band(score: float) -> CvssBand:
    if score <= 0:
        return CvssBand.NONE
    if score < 4:
        return CvssBand.LOW
    if score < 7:
        return CvssBand.MEDIUM
    if score < 9:
        return CvssBand.HIGH
    return CvssBand.CRITICAL


# ---------------------------------------------------------------- singleton

def _log_task_result(task: asyncio.Task[Any]) -> None:
    if task.cancelled():
        log.info("run task %s cancelled", task.get_name())
        return
    exc = task.exception()
    if exc is not None:
        log.error("run task %s raised: %r", task.get_name(), exc, exc_info=exc)


_singleton: RunOrchestrator | None = None


def get_orchestrator() -> RunOrchestrator:
    global _singleton
    if _singleton is None:
        _singleton = RunOrchestrator()
    return _singleton
