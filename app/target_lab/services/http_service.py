"""HTTP service — the most useful fake for CAI to interrogate.

Serves realistic Server banners and a handful of intentionally vulnerable
endpoints that match the ground-truth CVEs declared by each scenario.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from ..base import ServiceBase, ServiceMeta


@dataclass
class HttpRequest:
    method: str
    path: str
    version: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes


# Type alias for a per-request handler.
HttpHandler = tuple[str, str, "HttpEndpoint"]


class HttpEndpoint:
    """Base for a single request handler mounted on the fake HTTP service."""

    def matches(self, req: HttpRequest) -> bool:
        return True

    def respond(self, req: HttpRequest) -> HttpResponse:  # noqa: ARG002
        return HttpResponse(status=200, reason="OK", headers={}, body=b"")


class HttpService(ServiceBase):
    """Minimal HTTP/1.1 server with pluggable endpoints and realistic banners."""

    def __init__(
        self,
        meta: ServiceMeta,
        endpoints: list[HttpEndpoint] | None = None,
    ):
        super().__init__(meta)
        self.endpoints: list[HttpEndpoint] = endpoints or []
        # If unspecified, derive a plausible server banner from the version.
        self.server_banner = meta.banner_version or "Apache/2.4.6 (CentOS)"

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
        except TimeoutError:
            return
        if not request_line:
            return
        try:
            method, path, version = request_line.decode(
                "iso-8859-1", errors="replace"
            ).rstrip("\r\n").split(" ", 2)
        except ValueError:
            return

        headers: dict[str, str] = {}
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            except TimeoutError:
                break
            if line in (b"\r\n", b"\n", b""):
                break
            try:
                key, value = line.decode("iso-8859-1").rstrip("\r\n").split(":", 1)
                headers[key.strip().lower()] = value.strip()
            except ValueError:
                continue

        body = b""
        content_length = int(headers.get("content-length", "0") or "0")
        if content_length > 0:
            try:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=3.0
                )
            except (TimeoutError, asyncio.IncompleteReadError):
                body = b""

        req = HttpRequest(
            method=method.upper(),
            path=path,
            version=version,
            headers=headers,
            body=body,
        )

        # Dispatch to first matching endpoint, else default 404.
        resp: HttpResponse | None = None
        for ep in self.endpoints:
            if ep.matches(req):
                resp = ep.respond(req)
                break
        if resp is None:
            resp = HttpResponse(
                status=404, reason="Not Found", headers={}, body=b"Not Found"
            )

        # Realistic Server + Content-Length headers baked in.
        final_headers = {"Server": self.server_banner, **resp.headers}
        final_headers.setdefault("Content-Length", str(len(resp.body)))
        final_headers.setdefault("Content-Type", "text/plain")
        final_headers.setdefault("Connection", "close")

        header_bytes = f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode()
        for k, v in final_headers.items():
            header_bytes += f"{k}: {v}\r\n".encode()
        header_bytes += b"\r\n"

        writer.write(header_bytes + resp.body)
        await writer.drain()


class HttpsService(HttpService):
    """HTTPS variant. For simulation we serve plain HTTP on the HTTPS port —
    nmap still records the port as open with the declared version, and CAI's
    version-detection logic will read the banner as advertised. TLS setup would
    require certificates we don't need for a scanning-only proof-of-concept."""


# --- Common endpoints reused across scenarios ---


class RootBannerEndpoint(HttpEndpoint):
    """GET / — returns a plain-text hello with the service's declared banner."""

    def matches(self, req: HttpRequest) -> bool:
        return req.method in ("GET", "HEAD") and req.path in ("/", "/index.html")

    def respond(self, req: HttpRequest) -> HttpResponse:
        return HttpResponse(
            status=200,
            reason="OK",
            headers={"Content-Type": "text/html"},
            body=b"" if req.method == "HEAD" else b"<html><body>It works.</body></html>",
        )


class OptionsbleedEndpoint(HttpEndpoint):
    """CVE-2017-9798 — mangled Allow header on OPTIONS requests."""

    def matches(self, req: HttpRequest) -> bool:
        return req.method == "OPTIONS" and req.path.startswith("/")

    def respond(self, req: HttpRequest) -> HttpResponse:  # noqa: ARG002
        mangled = "GET,HEAD,POST,OPTIONS,,,,,,,,,,,,POST,,,,,POST"
        return HttpResponse(
            status=200,
            reason="OK",
            headers={"Allow": mangled, "Content-Type": "text/plain"},
            body=b"",
        )


class ServerStatusEndpoint(HttpEndpoint):
    """Apache mod_status leak — reveals server hostname + PID list."""

    def matches(self, req: HttpRequest) -> bool:
        return req.method in ("GET", "HEAD") and req.path.startswith("/server-status")

    def respond(self, req: HttpRequest) -> HttpResponse:  # noqa: ARG002
        body = (
            b"<html><body><h1>Apache Server Status for localhost</h1>"
            b"<p>Server Version: Apache/2.4.6 (CentOS)</p>"
            b"<p>Server MPM: prefork</p>"
            b"<p>Processes: 5 workers idle</p></body></html>"
        )
        return HttpResponse(
            status=200,
            reason="OK",
            headers={"Content-Type": "text/html"},
            body=body,
        )


class SpringActuatorEndpoint(HttpEndpoint):
    """Spring Boot /actuator/env exposure — mock of a common misconfiguration."""

    def matches(self, req: HttpRequest) -> bool:
        return req.method in ("GET", "HEAD") and req.path == "/actuator/env"

    def respond(self, req: HttpRequest) -> HttpResponse:  # noqa: ARG002
        body = (
            b'{"activeProfiles":["prod"],'
            b'"propertySources":[{"name":"systemEnvironment",'
            b'"properties":{"JAVA_HOME":{"value":"/opt/jdk-11"},'
            b'"DB_URL":{"value":"jdbc:postgresql://settlement-db:5432/settlement"}}}]}'
        )
        return HttpResponse(
            status=200,
            reason="OK",
            headers={"Content-Type": "application/json"},
            body=body,
        )


class Log4ShellEchoEndpoint(HttpEndpoint):
    """CVE-2021-44228 — echoes back the JNDI payload in a header, mimicking a
    downstream logger that eagerly parses ${jndi:...} references. Enough for
    nuclei's log4j-vuln-active template to flag the host as vulnerable."""

    _JNDI = re.compile(r"\$\{jndi:[^}]+\}")

    def matches(self, req: HttpRequest) -> bool:
        # Trigger on any header containing a JNDI-style substitution reference.
        return any(self._JNDI.search(v) for v in req.headers.values())

    def respond(self, req: HttpRequest) -> HttpResponse:
        for _key, value in req.headers.items():
            match = self._JNDI.search(value)
            if match:
                return HttpResponse(
                    status=200,
                    reason="OK",
                    headers={"X-Log4j-Echo": match.group(0), "Content-Type": "text/plain"},
                    body=b"logged",
                )
        return HttpResponse(status=200, reason="OK", headers={}, body=b"ok")


class VersionBannerOverride(HttpEndpoint):
    """Not really an endpoint — exists to force a Server-header override for a
    specific host when its default banner needs adjustment. Attach as the first
    endpoint; matches nothing, but reads well in the endpoint list."""

    def matches(self, req: HttpRequest) -> bool:  # noqa: ARG002
        return False

    def respond(self, req: HttpRequest) -> HttpResponse:  # noqa: ARG002
        return HttpResponse(status=200, reason="OK", headers={}, body=b"")
