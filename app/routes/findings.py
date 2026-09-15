from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.db import get_session
from app.db.models import FindingRow
from app.schemas.finding import BarrierTheme, Finding

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[Finding])
def list_findings(
    session: Session = Depends(get_session),
    theme: BarrierTheme | None = Query(default=None),
) -> list[Finding]:
    stmt = select(FindingRow)
    if theme:
        stmt = stmt.where(FindingRow.theme == theme.value)
    stmt = stmt.order_by(FindingRow.createdAt.desc())  # type: ignore[attr-defined]
    rows = session.exec(stmt).all()
    return [Finding.model_validate(r.payload) for r in rows]


@router.get("/{finding_id}", response_model=Finding)
def get_finding(finding_id: str, session: Session = Depends(get_session)) -> Finding:
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return Finding.model_validate(row.payload)
