"""Accidental-host-execution guard, NOT a network/firewall attestation.

Only known Apple Virtualization macOS guests are supported for the executor-side
entry point. The external controller must enforce and test the stronger contract.
There is deliberately no environment-variable or config override for this guard.
"""
from __future__ import annotations

import re
import subprocess

from policy import PolicyError


def require_macos_guest() -> None:
    try:
        model = subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.model"], text=True, timeout=5).strip()
        mounts = subprocess.check_output(["/sbin/mount"], text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PolicyError("isolation_required", "Cannot establish macOS guest identity; refusing native execution.") from exc
    if not re.fullmatch(r"VirtualMac[0-9]+,[0-9]+", model):
        raise PolicyError("isolation_required", "Executor-side worker must run inside a supported macOS VM, never on the personal Mac host.")
    if re.search(r"\b(virtiofs|smbfs|nfs|webdav|afpfs|9p)\b", mounts, re.IGNORECASE):
        raise PolicyError("host_sharing_forbidden", "Shared/network filesystems are not allowed in the job guest.")
