"""Translate a Scenario into a concrete list of loopback bindings + services.

Rule: the last octet of each host's IP is preserved on the loopback side using
the 127.0.42.0/24 block — so scenario host 10.42.0.10 binds to 127.0.42.10.
This avoids collisions with real localhost services on 127.0.0.1.
"""
from __future__ import annotations

from app.schemas.scenario import Scenario, TargetHost, TargetService

from .base import ServiceMeta
from .services import (
    HttpService,
    HttpsService,
    PostgresBannerService,
    RdpBannerService,
    SmbBannerService,
    SshBannerService,
)
from .services.http_service import (
    HttpEndpoint,
    Log4ShellEchoEndpoint,
    OptionsbleedEndpoint,
    RootBannerEndpoint,
    ServerStatusEndpoint,
    SpringActuatorEndpoint,
)

LAB_LOOPBACK_PREFIX = "127.0.42."


def bind_address_for(host: TargetHost) -> str:
    """Map scenario IP → lab loopback IP by preserving the last octet."""
    last_octet = host.ipAddress.rsplit(".", 1)[-1]
    return f"{LAB_LOOPBACK_PREFIX}{last_octet}"


def _service_meta(host: TargetHost, svc: TargetService) -> ServiceMeta:
    return ServiceMeta(
        hostname=host.hostname,
        address=bind_address_for(host),
        port=svc.port,
        protocol=svc.protocol,
        banner_service=svc.service,
        banner_version=svc.version,
    )


def _http_endpoints_for(scenario: Scenario, host: TargetHost) -> list[HttpEndpoint]:
    """Attach vulnerable endpoints to the HTTP service based on scenario ground truth."""
    endpoints: list[HttpEndpoint] = []

    # Any ground-truth vuln affecting this host + on http/https gets its endpoint.
    for gt in scenario.groundTruth:
        if gt.affectedHost != host.hostname:
            continue
        cve = (gt.cve or "").upper()

        if cve == "CVE-2017-9798":
            endpoints.append(OptionsbleedEndpoint())
            endpoints.append(ServerStatusEndpoint())
        elif cve == "CVE-2021-41773":
            # Path-traversal — we intentionally do NOT actually leak /etc/passwd
            # (safe simulation). But the version banner and Server-Status trick
            # will confirm the Apache identity, allowing CAI's version-based
            # false-positive behaviour to be observable.
            endpoints.append(ServerStatusEndpoint())
        elif cve == "CVE-2021-44228":
            endpoints.append(Log4ShellEchoEndpoint())
            endpoints.append(SpringActuatorEndpoint())

    # Root banner always last so specific handlers win.
    endpoints.append(RootBannerEndpoint())
    return endpoints


def build_services(scenario: Scenario) -> list[object]:
    """Produce a list of unstarted service instances for the given scenario."""
    services: list[object] = []
    for host in scenario.topology.hosts:
        for svc in host.services:
            meta = _service_meta(host, svc)
            impl = _pick_impl(scenario, host, svc, meta)
            if impl is not None:
                services.append(impl)
    return services


def _pick_impl(
    scenario: Scenario,
    host: TargetHost,
    svc: TargetService,
    meta: ServiceMeta,
) -> object | None:
    name = svc.service.lower()
    if name == "ssh":
        return SshBannerService(meta)
    if name == "smb":
        return SmbBannerService(meta)
    if name == "rdp":
        return RdpBannerService(meta)
    if name == "postgres":
        return PostgresBannerService(meta)
    if name in ("http",):
        return HttpService(meta, endpoints=_http_endpoints_for(scenario, host))
    if name == "https":
        # Plain HTTP on HTTPS port — sufficient for banner-scan detection.
        return HttpsService(meta, endpoints=_http_endpoints_for(scenario, host))
    # MySQL / IIS / IRC / IsoTsap etc. — skip, they need protocol-specific handling
    # we haven't built yet. Reported at start-time so operators see gaps clearly.
    return None
