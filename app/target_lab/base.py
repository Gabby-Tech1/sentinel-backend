from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger("target_lab")


@dataclass
class ServiceMeta:
    """Descriptor for a single fake service bound to loopback."""

    hostname: str
    address: str  # e.g. "127.0.0.10"
    port: int
    protocol: str  # "tcp" | "udp"
    banner_service: str  # e.g. "ssh", "http", "smb"
    banner_version: str | None = None


class ServiceBase(ABC):
    """Abstract asyncio TCP server one fake service binds to."""

    def __init__(self, meta: ServiceMeta):
        self.meta = meta
        self._server: asyncio.base_events.Server | None = None
        self._latency_ms: float = 0.0
        self._loss_percent: float = 0.0

    def apply_network_shim(self, latency_ms: float, loss_percent: float) -> None:
        """Configure per-connection latency and packet-loss simulation."""
        self._latency_ms = max(0.0, latency_ms)
        self._loss_percent = max(0.0, min(100.0, loss_percent))

    async def start(self) -> None:
        try:
            self._server = await asyncio.start_server(
                self._wrap_handle,
                self.meta.address,
                self.meta.port,
            )
        except OSError as exc:
            raise RuntimeError(
                f"Failed to bind {self.meta.address}:{self.meta.port} "
                f"for {self.meta.hostname}/{self.meta.banner_service}: {exc}"
            ) from exc
        log.info(
            "started %s://%s:%d (%s @ %s)",
            self.meta.banner_service,
            self.meta.address,
            self.meta.port,
            self.meta.hostname,
            self.meta.banner_version or "unknown",
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
        except TimeoutError:
            log.warning("timeout closing %s:%d", self.meta.address, self.meta.port)
        self._server = None

    async def _wrap_handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # Simulated packet loss — silently drop the connection.
        if self._loss_percent > 0:
            import random

            if random.uniform(0, 100) < self._loss_percent:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return

        # Simulated latency — sleep before responding.
        if self._latency_ms > 0:
            await asyncio.sleep(self._latency_ms / 1000.0)

        try:
            await self.handle(reader, writer)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("error in %s handler", self.meta.banner_service)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @abstractmethod
    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None: ...
