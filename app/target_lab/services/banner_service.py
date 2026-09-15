"""Banner-only TCP listeners.

These reproduce the byte-level greeting a real service sends on TCP connect,
which is what nmap uses for service/version detection. They do not implement
the underlying protocol — CAI cannot log in via these listeners, only detect
them and read their banners.
"""
from __future__ import annotations

import asyncio

from ..base import ServiceBase


class SshBannerService(ServiceBase):
    """Sends the SSH-2.0 banner then closes. Enough for nmap -sV to detect."""

    async def handle(
        self,
        reader: asyncio.StreamReader,  # noqa: ARG002
        writer: asyncio.StreamWriter,
    ) -> None:
        version = self.meta.banner_version or "OpenSSH 7.4"
        banner = f"SSH-2.0-{version.replace('OpenSSH ', 'OpenSSH_')}\r\n".encode()
        writer.write(banner)
        await writer.drain()


class SmbBannerService(ServiceBase):
    """SMB port listener. Responds to a probe with a canned NBSS reject.

    A real SMB negotiation is complex; nmap's smb-vuln scripts require it. We
    respond with just enough to be flagged as an open SMB port, and let the
    finding-generation logic decide what "vulnerabilities" apply based on the
    scenario's banner_version metadata.
    """

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await asyncio.wait_for(reader.read(4), timeout=1.0)
        except (TimeoutError, Exception):
            pass
        # NBSS session request negative response (0x83) — enough for nmap
        # to record SMB as present.
        writer.write(b"\x83\x00\x00\x01\x82")
        await writer.drain()


class RdpBannerService(ServiceBase):
    """RDP port listener — nmap only needs the connection to succeed."""

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await asyncio.wait_for(reader.read(19), timeout=1.0)
        except (TimeoutError, Exception):
            pass
        # X.224 Connection Confirm — minimal RDP handshake response.
        writer.write(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
        await writer.drain()


class PostgresBannerService(ServiceBase):
    """PostgreSQL greeting response. Enough for nmap pgsql-version."""

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await asyncio.wait_for(reader.read(8), timeout=1.0)
        except (TimeoutError, Exception):
            pass
        # 'R' = authentication request, code 3 = cleartext password.
        writer.write(b"R\x00\x00\x00\x08\x00\x00\x00\x03")
        await writer.drain()
