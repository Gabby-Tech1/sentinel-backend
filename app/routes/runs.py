import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlmodel import Session, select
from sse_starlette.sse import EventSourceResponse

from app.agent import CLAUDE_DEFAULT_MODEL, ClaudeAgent, StubAgent, get_orchestrator
from app.db import get_session
from app.db.models import RunRow, ScenarioRow
from app.schemas.run import Run, RunStatus
from app.schemas.scenario import Scenario

router = APIRouter(prefix="/runs", tags=["runs"])


class StartRunRequest(BaseModel):
    scenarioId: str
    agent: str = "stub"  # "stub" | "claude"
    model: str | None = None  # only used when agent == "claude"; defaults to CLAUDE_DEFAULT_MODEL


@router.get("", response_model=list[Run])
def list_runs(
    session: Session = Depends(get_session),
    scenario_id: str | None = Query(default=None, alias="scenarioId"),
    status: RunStatus | None = Query(default=None),
) -> list[Run]:
    stmt = select(RunRow)
    if scenario_id:
        stmt = stmt.where(RunRow.scenarioId == scenario_id)
    if status:
        stmt = stmt.where(RunRow.status == status.value)
    stmt = stmt.order_by(RunRow.startedAt.desc())  # type: ignore[attr-defined]
    rows = session.exec(stmt).all()
    return [Run.model_validate(r.payload) for r in rows]


@router.get("/{run_id}", response_model=Run)
def get_run(run_id: str, session: Session = Depends(get_session)) -> Run:
    row = session.get(RunRow, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return Run.model_validate(row.payload)


@router.post("", response_model=Run, status_code=201)
async def start_run(
    req: StartRunRequest, session: Session = Depends(get_session)
) -> Run:
    scenario_row = session.get(ScenarioRow, req.scenarioId)
    if scenario_row is None:
        raise HTTPException(
            status_code=404, detail=f"Scenario '{req.scenarioId}' not found"
        )
    scenario = Scenario.model_validate(scenario_row.payload)

    orch = get_orchestrator()
    if orch.current_run_id is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A run is already in progress ({orch.current_run_id}). "
                f"Cancel it before starting another."
            ),
        )

    if req.agent == "stub":
        agent = StubAgent()
    elif req.agent == "claude":
        try:
            agent = ClaudeAgent(model=req.model or CLAUDE_DEFAULT_MODEL)
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown agent '{req.agent}' (expected 'stub' or 'claude')",
        )

    return await orch.start(scenario, agent)


@router.post("/{run_id}/cancel", response_model=Run)
async def cancel_run(run_id: str) -> Run:
    orch = get_orchestrator()
    if orch.current_run_id != run_id:
        raise HTTPException(
            status_code=409, detail=f"Run '{run_id}' is not the currently-active run."
        )
    run = await orch.cancel()
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return run


@router.get("/{run_id}/events")
async def stream_events(run_id: str, request: Request):
    """Server-Sent Events channel for the live view.

    Emits `snapshot` (once, current run state), then `event` per new event,
    then `done` (status transition).
    """
    orch = get_orchestrator()

    async def event_source():
        async for msg in orch.subscribe(run_id):
            # Client-disconnect guard so we don't keep a dead subscriber.
            if await request.is_disconnected():
                break
            yield {"event": msg.get("type", "message"), "data": json.dumps(msg)}

    return EventSourceResponse(event_source())
