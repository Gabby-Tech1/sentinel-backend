from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BarrierTheme(str, Enum):
    TECHNICAL = "technical"
    HUMAN_CAPACITY = "human_capacity"
    GOVERNANCE = "governance"
    ECONOMIC = "economic"


class FindingImplication(str, Enum):
    INFORMATIONAL = "informational"
    ACTIONABLE = "actionable"
    BLOCKING = "blocking"


class Finding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    theme: BarrierTheme
    implication: FindingImplication
    description: str
    evidenceExcerpt: str
    supportingRunIds: list[str] = Field(default_factory=list)
    relatedScenarioIds: list[str] = Field(default_factory=list)
    researchQuestion: Literal["RQ1", "RQ2", "RQ3", "RQ4"]
    notes: str | None = None
    createdAt: datetime
