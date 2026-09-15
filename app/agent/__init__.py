"""Agent package — the CAI worker that drives runs.

The `Agent` interface is the swap point between the stub agent shipped in
S2.3 and the real Anthropic-backed CAI agent that lands when the user plugs
in ANTHROPIC_API_KEY. Both implementations produce the same stream of
`Decision`s; only the reasoning behind those decisions changes.
"""

from .base import Agent, Decision, Finish, RecordFinding, RunTool, Think, TripGuardrail
from .claude_agent import DEFAULT_MODEL as CLAUDE_DEFAULT_MODEL
from .claude_agent import ClaudeAgent
from .runner import RunOrchestrator, get_orchestrator
from .stub_agent import StubAgent
from .tools import ToolExecutor, ToolResult

__all__ = [
    "Agent",
    "CLAUDE_DEFAULT_MODEL",
    "ClaudeAgent",
    "Decision",
    "Finish",
    "RecordFinding",
    "RunOrchestrator",
    "RunTool",
    "StubAgent",
    "Think",
    "ToolExecutor",
    "ToolResult",
    "TripGuardrail",
    "get_orchestrator",
]
