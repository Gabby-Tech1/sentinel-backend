from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from .base import ServiceMeta


class LabServiceStatus(BaseModel):
    hostname: str
    address: str
    port: int
    protocol: str
    banner_service: str
    banner_version: str | None = None
    status: Literal["listening", "failed"] = "listening"
    error: str | None = None

    @classmethod
    def from_meta(
        cls, meta: ServiceMeta, status: str = "listening", error: str | None = None
    ) -> LabServiceStatus:
        return cls(
            hostname=meta.hostname,
            address=meta.address,
            port=meta.port,
            protocol=meta.protocol,
            banner_service=meta.banner_service,
            banner_version=meta.banner_version,
            status=status,  # type: ignore[arg-type]
            error=error,
        )


class LabState(BaseModel):
    scenarioId: str | None = None
    startedAt: datetime | None = None
    services: list[LabServiceStatus] = Field(default_factory=list)
    latencyMs: float = 0.0
    packetLossPercent: float = 0.0

    @property
    def running(self) -> bool:
        return self.scenarioId is not None and len(self.services) > 0

    @classmethod
    def idle(cls) -> LabState:
        return cls()

    @classmethod
    def make(
        cls,
        scenario_id: str,
        services: list[LabServiceStatus],
        latency_ms: float,
        loss_percent: float,
    ) -> LabState:
        return cls(
            scenarioId=scenario_id,
            startedAt=datetime.now(UTC),
            services=services,
            latencyMs=latency_ms,
            packetLossPercent=loss_percent,
        )
