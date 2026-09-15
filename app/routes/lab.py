from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.db import get_session
from app.db.models import ScenarioRow
from app.schemas.scenario import Scenario
from app.target_lab import LabState, get_lab

router = APIRouter(prefix="/lab", tags=["lab"])


@router.get("/status", response_model=LabState)
def lab_status() -> LabState:
    return get_lab().state


@router.post("/{scenario_id}/start", response_model=LabState)
async def lab_start(scenario_id: str, session: Session = Depends(get_session)) -> LabState:
    row = session.get(ScenarioRow, scenario_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    scenario = Scenario.model_validate(row.payload)
    return await get_lab().start(scenario)


@router.post("/stop", response_model=LabState)
async def lab_stop() -> LabState:
    return await get_lab().stop()
