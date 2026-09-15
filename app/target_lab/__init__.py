"""Target lab — Python-based simulated vulnerable network.

Each scenario in the scenario library maps to a set of loopback listeners
(127.0.0.X:PORT) that mimic the banners, ports, and vulnerable behaviour of
the declared services. CAI can then run real nmap/nuclei/curl against these
listeners as if they were remote hosts — without needing Docker or VMs.
"""

from .lab import LabRunner, get_lab
from .state import LabState

__all__ = ["LabRunner", "LabState", "get_lab"]
