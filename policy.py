"""Identifier and device rules for the worker API.

Client requests name revisions, artifacts, sessions, and device UDIDs.
They never name a host path or a shell command.
"""

from __future__ import annotations

import re
from pathlib import Path

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
UDID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
SCHEME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_+.\-]{0,63}$")

# Leo's booted iPhone 17. Shutdown of this device is never a scheduler action.
BUILTIN_PERSONAL_DEVICES = frozenset({"4D015300-4BAE-4E6D-89C9-BC4D454E4216"})


class PolicyError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise PolicyError("invalid_id", f"{label} must be a short token, not a path.")
    return value


def require_scheme(value: object) -> str:
    if not isinstance(value, str) or not SCHEME_RE.fullmatch(value):
        raise PolicyError("invalid_scheme", "Scheme name is not allowed.")
    return value


def normalize_udid(value: object) -> str:
    if not isinstance(value, str) or not UDID_RE.fullmatch(value):
        raise PolicyError("invalid_device", "Device id must be a simulator UDID.")
    return value.upper()


def check_device(device_id: str, allowlist: set[str], denylist: set[str]) -> str:
    udid = normalize_udid(device_id)
    denied = {item.upper() for item in denylist} | {item.upper() for item in BUILTIN_PERSONAL_DEVICES}
    if udid in denied:
        raise PolicyError(
            "personal_simulator",
            "That simulator belongs to the personal account and will not be shut down or reused.",
        )
    allowed = {item.upper() for item in allowlist}
    if udid not in allowed:
        raise PolicyError("device_not_allowed", "Device id is not in the worker allowlist.")
    return udid


def require_under(path: Path, root: Path) -> Path:
    """Resolve path and require it stay inside root, after following links."""
    root_resolved = root.resolve()
    resolved = path.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise PolicyError("path_escape", "Path is outside the worker root.")
    return resolved
