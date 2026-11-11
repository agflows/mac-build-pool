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


def require_recipe(value: object) -> str:
    if value not in ("expo-ios", "flutter-ios", "swift-ios"):
        raise PolicyError("invalid_recipe", "Recipe must be expo-ios, flutter-ios or swift-ios.")
    return value


def require_configuration(value: object) -> str:
    if value not in ("Debug", "Release"):
        raise PolicyError("invalid_configuration", "Configuration must be Debug or Release.")
    return value


def require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError("invalid_body", label + " must be a boolean.")
    return value


def require_public_env(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 32:
        raise PolicyError("invalid_environment", "publicEnv must contain at most 32 EXPO_PUBLIC_ variables.")
    for key, text in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"EXPO_PUBLIC_[A-Z0-9_]{1,80}", key):
            raise PolicyError("invalid_environment", "Only EXPO_PUBLIC_ variables may be supplied.")
        if not isinstance(text, str) or len(text) > 4096 or "\x00" in text:
            raise PolicyError("invalid_environment", "Public environment values must be short strings without NUL.")
    return dict(value)


def require_under(path: Path, root: Path) -> Path:
    """Resolve path and require it stay inside root, after following links."""
    root_resolved = root.resolve()
    resolved = path.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise PolicyError("path_escape", "Path is outside the worker root.")
    return resolved
