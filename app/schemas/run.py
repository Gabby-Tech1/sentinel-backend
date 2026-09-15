from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .scenario import CvssBand, KillChainPhase


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    HALTED = "halted"


class ModelProvider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    OLLAMA_LOCAL = "ollama-local"


class ModelConfig(BaseModel):
    provider: ModelProvider
    model: str
    temperature: float = Field(ge=0, le=2)
    contextWindow: int = Field(gt=0)


class ResourceSample(BaseModel):
    t: float
    cpuPercent: float = Field(ge=0, le=100)
    memoryMb: float = Field(ge=0)
    tokensPerSec: float = Field(ge=0)
    toolCallsPerMin: float = Field(ge=0)


class _EventBase(BaseModel):
    id: str
    index: int = Field(ge=0)
    t: float
    durationMs: float | None = Field(default=None, ge=0)
    phase: KillChainPhase | None = None


class ThinkEvent(_EventBase):
    type: Literal["think"] = "think"
    content: str
    tokensIn: int = Field(ge=0)
    tokensOut: int = Field(ge=0)


class ToolCallEvent(_EventBase):
    type: Literal["tool_call"] = "tool_call"
    tool: str
    toolCategory: Literal[
        "reconnaissance",
        "exploitation",
        "privilege_escalation",
        "lateral_movement",
        "exfiltration",
        "command_and_control",
        "utility",
    ]
    args: dict[str, Any]
    command: str | None = None
    exitCode: int | None = None
    output: str
    outputTruncated: bool = False


class ObservationEvent(_EventBase):
    type: Literal["observation"] = "observation"
    summary: str
    detail: str | None = None


class GuardrailEvent(_EventBase):
    type: Literal["guardrail"] = "guardrail"
    layer: Literal["prompt_injection", "tool_abuse", "policy", "human_in_loop"]
    decision: Literal["blocked", "warned", "deferred"]
    reason: str
    triggeringInput: str | None = None


class FindingEvent(_EventBase):
    type: Literal["finding"] = "finding"
    vulnerabilityId: str
    cve: str | None = None
    title: str
    cvssScore: float = Field(ge=0, le=10)
    band: CvssBand
    affectedHost: str
    evidence: str


class OutputEvent(_EventBase):
    type: Literal["output"] = "output"
    content: str


class ErrorEvent(_EventBase):
    type: Literal["error"] = "error"
    message: str
    recoverable: bool


RunEvent = (
    ThinkEvent
    | ToolCallEvent
    | ObservationEvent
    | GuardrailEvent
    | FindingEvent
    | OutputEvent
    | ErrorEvent
)


class RunMetrics(BaseModel):
    durationMs: float = Field(ge=0)
    totalTokensIn: int = Field(ge=0)
    totalTokensOut: int = Field(ge=0)
    estimatedCostUSD: float = Field(ge=0)
    toolCallCount: int = Field(ge=0)
    vulnsFoundCount: int = Field(ge=0)
    truePositives: int = Field(ge=0)
    falsePositives: int = Field(ge=0)
    falseNegatives: int = Field(ge=0)
    guardrailTripCount: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)


class Run(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenarioId: str
    scenarioName: str
    status: RunStatus
    model: ModelConfig
    startedAt: datetime
    endedAt: datetime | None = None
    progress: float = Field(ge=0, le=1)
    currentPhase: KillChainPhase | None = None
    metrics: RunMetrics
    events: list[RunEvent] = Field(default_factory=list)
    resourceSeries: list[ResourceSample] = Field(default_factory=list)
    notes: str | None = None
