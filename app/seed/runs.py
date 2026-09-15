"""Run seed table.

Empty by design: real runs are produced by the CAI runner (stub or Claude)
via POST /runs. Anything shown on the dashboard should come from an actual
execution, not from hand-crafted fixtures.
"""
from __future__ import annotations

from app.schemas.run import Run

SEED_RUNS: list[Run] = []
