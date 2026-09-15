from __future__ import annotations

import logging

from app.schemas.scenario import ResourceProfile, Scenario

from .base import ServiceBase, ServiceMeta
from .manifest import build_services
from .state import LabServiceStatus, LabState

log = logging.getLogger("target_lab")

# Latency & loss defaults derived from the scenario's resource profile.
_PROFILE_SHIM: dict[str, tuple[float, float]] = {
    ResourceProfile.DEVELOPING_LOW.value: (120.0, 6.5),
    ResourceProfile.DEVELOPING_MID.value: (40.0, 1.2),
    ResourceProfile.MODERN.value: (5.0, 0.0),
}


class LabRunner:
    """Owns the single active lab instance. Not thread-safe — call from the
    same asyncio loop (i.e. from within FastAPI request handlers)."""

    def __init__(self):
        self._services: list[ServiceBase] = []
        self._state: LabState = LabState.idle()

    @property
    def state(self) -> LabState:
        return self._state

    async def start(self, scenario: Scenario) -> LabState:
        if self._services:
            await self.stop()

        services = build_services(scenario)
        latency_ms, loss = _PROFILE_SHIM.get(
            scenario.topology.resourceProfile.value, (0.0, 0.0)
        )
        # Scenario-level override — some scenarios explicitly declare loss.
        network_loss = scenario.topology.network.averagePacketLossPercent
        if network_loss > loss:
            loss = network_loss

        statuses: list[LabServiceStatus] = []
        started: list[ServiceBase] = []
        for svc in services:
            assert isinstance(svc, ServiceBase)  # noqa: S101
            svc.apply_network_shim(latency_ms, loss)
            try:
                await svc.start()
                started.append(svc)
                statuses.append(LabServiceStatus.from_meta(svc.meta))
            except RuntimeError as exc:
                log.warning("skipping %s: %s", svc.meta.banner_service, exc)
                statuses.append(
                    LabServiceStatus.from_meta(svc.meta, status="failed", error=str(exc))
                )

        # Track what we skipped in the manifest so the frontend can surface it.
        for host in scenario.topology.hosts:
            for tsvc in host.services:
                # If no matching binding was produced (unsupported protocol),
                # record it as a skipped service so operators know.
                if not any(
                    s.address == f"127.0.42.{host.ipAddress.rsplit('.', 1)[-1]}"
                    and s.port == tsvc.port
                    for s in statuses
                ):
                    statuses.append(
                        LabServiceStatus(
                            hostname=host.hostname,
                            address=f"127.0.42.{host.ipAddress.rsplit('.', 1)[-1]}",
                            port=tsvc.port,
                            protocol=tsvc.protocol,
                            banner_service=tsvc.service,
                            banner_version=tsvc.version,
                            status="failed",
                            error="protocol not yet supported in target_lab",
                        )
                    )

        self._services = started
        self._state = LabState.make(scenario.id, statuses, latency_ms, loss)
        log.info(
            "lab started for %s: %d services live, %d skipped",
            scenario.id,
            sum(1 for s in statuses if s.status == "listening"),
            sum(1 for s in statuses if s.status == "failed"),
        )
        return self._state

    async def stop(self) -> LabState:
        for svc in self._services:
            try:
                await svc.stop()
            except Exception:  # noqa: BLE001
                log.exception("error stopping %s", svc.meta.banner_service)
        self._services = []
        self._state = LabState.idle()
        return self._state


_singleton: LabRunner | None = None


def get_lab() -> LabRunner:
    global _singleton
    if _singleton is None:
        _singleton = LabRunner()
    return _singleton


__all__ = ["LabRunner", "ServiceMeta", "get_lab"]
