"""Standalone lab runner — start a scenario from the command line.

Usage:
    python -m app.target_lab start scn-recon-min-gov
    python -m app.target_lab list

Once running, the process holds the ports open until you Ctrl-C.
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import sys

from app.seed.scenarios import SEED_SCENARIOS

from .lab import LabRunner


def _find_scenario(id_or_slug: str):
    for scn in SEED_SCENARIOS:
        if scn.id == id_or_slug or scn.slug == id_or_slug:
            return scn
    return None


async def _run(scenario_id: str) -> int:
    scenario = _find_scenario(scenario_id)
    if scenario is None:
        print(f"Unknown scenario '{scenario_id}'.", file=sys.stderr)
        print("Available:", file=sys.stderr)
        for s in SEED_SCENARIOS:
            print(f"  - {s.id}  ({s.slug})", file=sys.stderr)
        return 2

    lab = LabRunner()
    state = await lab.start(scenario)
    live = [s for s in state.services if s.status == "listening"]
    skipped = [s for s in state.services if s.status == "failed"]
    print(f"\nLab started for scenario: {scenario.name}")
    print(f"  Resource profile: {scenario.topology.resourceProfile.value}")
    print(f"  Simulated latency: {state.latencyMs:.0f} ms, loss: {state.packetLossPercent:.1f}%")
    print(f"\nListening ({len(live)} services):")
    for s in live:
        version = f" [{s.banner_version}]" if s.banner_version else ""
        print(f"  {s.address}:{s.port:<5}  {s.banner_service:<10} {s.hostname}{version}")
    if skipped:
        print(f"\nSkipped ({len(skipped)} services — protocol not supported):")
        for s in skipped:
            print(f"  {s.address}:{s.port:<5}  {s.banner_service:<10} {s.hostname}")
    print("\nHit Ctrl-C to stop.\n")

    stop_event = asyncio.Event()

    def _handle_signal(*_: object) -> None:
        stop_event.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                asyncio.get_event_loop().add_signal_handler(sig, _handle_signal)
            except (NotImplementedError, RuntimeError):
                # Windows doesn't support add_signal_handler on ProactorEventLoop.
                pass

        await stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down…")
        await lab.stop()
    return 0


def _list() -> int:
    for s in SEED_SCENARIOS:
        print(f"  {s.id:<30}  {s.name}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Target lab runner")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Start the lab for a scenario")
    start.add_argument("scenario", help="Scenario id or slug")

    sub.add_parser("list", help="List available scenarios")

    args = parser.parse_args()
    if args.command == "start":
        # KeyboardInterrupt-friendly on Windows.
        try:
            return asyncio.run(_run(args.scenario))
        except KeyboardInterrupt:
            print("\nShutting down…")
            return 0
    if args.command == "list":
        return _list()
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
