from fastapi import APIRouter
from pydantic import BaseModel

from app.agent import CLAUDE_DEFAULT_MODEL
from app.config import settings

router = APIRouter(prefix="/meta", tags=["meta"])


class AgentAvailability(BaseModel):
    id: str
    name: str
    available: bool
    default_model: str | None = None
    reason: str | None = None


class Capabilities(BaseModel):
    """What the backend can do right now. The frontend reads this to decide
    whether to expose the Claude agent in the run picker, whether to show
    'add ANTHROPIC_API_KEY' hints, etc."""

    agents: list[AgentAvailability]
    claude_default_model: str


@router.get("/capabilities", response_model=Capabilities)
def capabilities() -> Capabilities:
    claude_available = bool(settings.anthropic_api_key)
    return Capabilities(
        claude_default_model=CLAUDE_DEFAULT_MODEL,
        agents=[
            AgentAvailability(
                id="stub",
                name="Stub CAI",
                available=True,
                default_model="stub-agent-v1",
                reason=None,
            ),
            AgentAvailability(
                id="claude",
                name="Claude",
                available=claude_available,
                default_model=CLAUDE_DEFAULT_MODEL,
                reason=(
                    None
                    if claude_available
                    else "ANTHROPIC_API_KEY not set on the backend."
                ),
            ),
        ],
    )
