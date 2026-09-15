from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.db.models import FrameworkRow
from app.schemas.framework import Framework

router = APIRouter(prefix="/framework", tags=["framework"])


@router.get("", response_model=Framework)
def get_framework(session: Session = Depends(get_session)) -> Framework:
    row = session.exec(select(FrameworkRow)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Framework not seeded")
    return Framework.model_validate(row.payload)
