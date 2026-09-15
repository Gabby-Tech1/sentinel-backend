from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class ScenarioRow(SQLModel, table=True):
    __tablename__ = "scenarios"
    id: str = Field(primary_key=True)
    slug: str = Field(index=True)
    name: str
    researchQuestion: str = Field(index=True)
    payload: dict[str, Any] = Field(sa_column=Column(JSON))


class RunRow(SQLModel, table=True):
    __tablename__ = "runs"
    id: str = Field(primary_key=True)
    scenarioId: str = Field(index=True, foreign_key="scenarios.id")
    scenarioName: str
    status: str = Field(index=True)
    startedAt: datetime = Field(index=True)
    endedAt: datetime | None = None
    payload: dict[str, Any] = Field(sa_column=Column(JSON))


class FindingRow(SQLModel, table=True):
    __tablename__ = "findings"
    id: str = Field(primary_key=True)
    theme: str = Field(index=True)
    researchQuestion: str = Field(index=True)
    createdAt: datetime = Field(index=True)
    payload: dict[str, Any] = Field(sa_column=Column(JSON))


class FrameworkRow(SQLModel, table=True):
    __tablename__ = "framework"
    name: str = Field(primary_key=True)
    version: str
    payload: dict[str, Any] = Field(sa_column=Column(JSON))
