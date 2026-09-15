from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.db.models import ScenarioRow
from app.schemas.scenario import Scenario

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.get("", response_model=list[Scenario])
def list_scenarios(session: Session = Depends(get_session)) -> list[Scenario]:
    rows = session.exec(select(ScenarioRow)).all()
    return [Scenario.model_validate(r.payload) for r in rows]


@router.get("/{scenario_id}", response_model=Scenario)
def get_scenario(scenario_id: str, session: Session = Depends(get_session)) -> Scenario:
    row = session.get(ScenarioRow, scenario_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return Scenario.model_validate(row.payload)
