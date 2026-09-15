from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CvssBand(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class KillChainPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    REPORTING = "reporting"


class CyberFunction(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    SIMULATED_EXPLOITATION = "simulated_exploitation"
    GUARDRAIL_STRESS = "guardrail_stress"
    AUTOMATED_RESPONSE = "automated_response"
    REPORTING = "reporting"


class ResourceProfile(str, Enum):
    DEVELOPING_LOW = "developing-country-low"
    DEVELOPING_MID = "developing-country-mid"
    MODERN = "modern"


class TargetService(BaseModel):
    port: int = Field(gt=0)
    protocol: Literal["tcp", "udp"]
    service: str
    version: str | None = None
    banner: str | None = None


class TargetHost(BaseModel):
    hostname: str
    ipAddress: str
    os: str
    osVersion: str
    role: str
    services: list[TargetService]
    patchLevel: Literal["legacy", "stale", "current"]
    notes: str | None = None


class TargetNetwork(BaseModel):
    cidr: str
    bandwidthMbps: float = Field(ge=0)
    intermittentConnectivity: bool
    averagePacketLossPercent: float = Field(ge=0, le=100)


class TargetTopology(BaseModel):
    hosts: list[TargetHost]
    network: TargetNetwork
    resourceProfile: ResourceProfile


class GroundTruthVuln(BaseModel):
    id: str
    cve: str | None = None
    title: str
    cvssScore: float = Field(ge=0, le=10)
    affectedHost: str
    affectedService: str | None = None
    category: str


class Scenario(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    slug: str
    name: str
    objective: str
    functions: list[CyberFunction]
    researchQuestion: Literal["RQ1", "RQ2", "RQ3", "RQ4"]
    complexity: int = Field(ge=1, le=5)
    expectedDurationMinutes: int = Field(gt=0)
    topology: TargetTopology
    groundTruth: list[GroundTruthVuln]
    parameters: dict[str, str | int | float | bool]
    tags: list[str]
    lastRunAt: datetime | None = None
