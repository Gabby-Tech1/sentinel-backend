from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal

from app.schemas.scenario import KillChainPhase, Scenario

# --- Decisions ------------------------------------------------------------

@dataclass
class Think:
    content: str
    tokens_in: int = 0
    tokens_out: int = 0
    phase: KillChainPhase | None = None


@dataclass
class RunTool:
    tool: str
    tool_category: Literal[
        "reconnaissance",
        "exploitation",
        "privilege_escalation",
        "lateral_movement",
        "exfiltration",
        "command_and_control",
        "utility",
    ]
    args: dict[str, Any]
    phase: KillChainPhase | None = None


@dataclass
class Observation:
    summary: str
    detail: str | None = None
    phase: KillChainPhase | None = None


@dataclass
class RecordFinding:
    vulnerability_id: str
    title: str
    cvss_score: float
    affected_host: str
    evidence: str
    cve: str | None = None
    phase: KillChainPhase | None = None


@dataclass
class TripGuardrail:
    layer: Literal["prompt_injection", "tool_abuse", "policy", "human_in_loop"]
    decision: Literal["blocked", "warned", "deferred"]
    reason: str
    triggering_input: str | None = None
    phase: KillChainPhase | None = None


@dataclass
class Finish:
    summary: str


Decision = Think | RunTool | Observation | RecordFinding | TripGuardrail | Finish


# --- Agent interface ------------------------------------------------------

@dataclass
class AgentContext:
    """Everything an agent may inspect during a run."""

    scenario: Scenario
    lab_prefix: str = "127.0.42."
    # Freeform key/value store passed between runner iterations for agents that
    # need to remember state (e.g. what ports were open on the last host).
    scratch: dict[str, Any] = field(default_factory=dict)


class Agent(ABC):
    """Async producer of decisions for a given scenario.

    Every yielded `Think`/`Observation` is a narration event.
    Every `RunTool` is executed by the runner, and its result becomes the
    input for the agent's next decision.
    """

    @abstractmethod
    def plan(
        self,
        ctx: AgentContext,
        tool_results: dict[str, Any],
    ) -> AsyncIterator[Decision]:
        """Yield decisions one at a time.

        `tool_results` is an accumulator populated by the runner after each
        `RunTool` yield; the agent can inspect it to decide what to do next.
        """
        ...
