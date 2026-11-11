"""Memory admission based on pressure level and swap activity.

Free-page counts are not an input. A machine can look short on free RAM while
still healthy, and it can be swapping hard with a comfortable free list.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

# kern.memorystatus_vm_pressure_level, from xnu kern_memorystatus.h
PRESSURE_NORMAL = 0x1
PRESSURE_WARNING = 0x2
PRESSURE_URGENT = 0x4
PRESSURE_CRITICAL = 0x8

PRESSURE_NAMES = {
    PRESSURE_NORMAL: "normal",
    PRESSURE_WARNING: "warning",
    PRESSURE_URGENT: "urgent",
    PRESSURE_CRITICAL: "critical",
}

# About 4 MiB of paging between samples counts as active swap.
SWAP_PAGE_DELTA = 256


@dataclass(frozen=True)
class MemorySample:
    pressure_level: int
    swapins: int
    swapouts: int

    @property
    def pressure_name(self) -> str:
        return PRESSURE_NAMES.get(self.pressure_level, f"level-{self.pressure_level}")


def swap_is_active(previous: MemorySample | None, current: MemorySample) -> bool:
    if previous is None:
        return False
    outs = current.swapouts - previous.swapouts
    ins = current.swapins - previous.swapins
    if outs < 0 or ins < 0:
        return False
    return outs >= SWAP_PAGE_DELTA or ins >= SWAP_PAGE_DELTA


def boot_needs_approval(previous: MemorySample | None, current: MemorySample, approved: bool) -> bool:
    """True when starting a simulator should wait for an operator."""
    if approved:
        return False
    if current.pressure_level >= PRESSURE_WARNING:
        return True
    return swap_is_active(previous, current)


def build_needs_approval(previous: MemorySample | None, current: MemorySample, approved: bool) -> bool:
    """Compiles are allowed at warning. Urgent pressure or live swapping waits."""
    if approved:
        return False
    if current.pressure_level >= PRESSURE_URGENT:
        return True
    return swap_is_active(previous, current)


def sample_system() -> MemorySample:
    level = int(
        subprocess.check_output(
            ["/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"],
            text=True,
        ).strip()
    )
    vm_stat = subprocess.check_output(["/usr/bin/vm_stat"], text=True)
    swapins = _vm_counter(vm_stat, "Swapins")
    swapouts = _vm_counter(vm_stat, "Swapouts")
    return MemorySample(pressure_level=level, swapins=swapins, swapouts=swapouts)


def _vm_counter(vm_stat: str, name: str) -> int:
    match = re.search(rf"^{name}:\s+(\d+)\.", vm_stat, re.MULTILINE)
    if not match:
        raise RuntimeError(f"vm_stat did not report {name}")
    return int(match.group(1))
