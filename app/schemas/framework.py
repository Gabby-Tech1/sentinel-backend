from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class FrameworkStage(str, Enum):
    FOUNDATION = "foundation"
    PILOT = "pilot"
    INTEGRATION = "integration"
    OPERATION = "operation"
    OPTIMIZATION = "optimization"


class FrameworkPrinciple(BaseModel):
    id: str
    title: str
    rationale: str
    supportingFindingIds: list[str] = Field(default_factory=list)


class ImplementationStep(BaseModel):
    stage: FrameworkStage
    action: str


class FrameworkPillar(BaseModel):
    id: str
    name: str
    summary: str
    iconKey: str
    principles: list[FrameworkPrinciple]
    implementationStages: list[ImplementationStep]


class MaturityStep(BaseModel):
    stage: FrameworkStage
    label: str
    description: str


class Framework(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    version: str
    statement: str
    pillars: list[FrameworkPillar]
    maturityLadder: list[MaturityStep]
