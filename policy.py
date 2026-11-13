"""Identifier and device rules for the worker API.

Client requests name revisions, artifacts, sessions, and device UDIDs.
They never name a host path or a shell command.
"""

from __future__ import annotations

import re
import math
from pathlib import Path

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
UDID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
SCHEME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_+.\-]{0,63}$")
SNAPSHOT_RE = re.compile(r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")
ELEMENT_REF_RE = re.compile(r"^e[1-9][0-9]{0,7}$")
SIMULATOR_UI_ACTIONS = frozenset({
    "snapshot", "tapElement", "tapMatching", "holdElement", "scrollElement", "typeInto", "waitFor", "batch",
})
MAX_INPUT_BATCH = 8
MAX_PREVIEW_BYTES = 512 * 1024
GESTURE_PRESETS = frozenset({
    "scroll-up", "scroll-down", "scroll-left", "scroll-right",
    "swipe-from-left-edge", "swipe-from-right-edge", "swipe-from-top-edge",
    "swipe-from-bottom-edge", "swipe-from-top-right-corner",
})
CONTENT_SIZES = frozenset({
    "extra-small", "small", "medium", "large", "extra-large", "extra-extra-large",
    "extra-extra-extra-large", "accessibility-medium", "accessibility-large",
    "accessibility-extra-large", "accessibility-extra-extra-large", "accessibility-extra-extra-extra-large",
})

# Leo's booted iPhone 17. Shutdown of this device is never a scheduler action.
BUILTIN_PERSONAL_DEVICES = frozenset({"4D015300-4BAE-4E6D-89C9-BC4D454E4216"})


def simulator_input(body):
    """Translate a bounded input request to AXe arguments, without target selection."""
    def invalid():
        return PolicyError("invalid_body", "Invalid simulator input action or parameters.")

    if not isinstance(body, dict) or not isinstance(body.get("action"), str):
        raise invalid()
    action = body["action"]
    if action == "batch":
        if set(body) != {"action", "snapshotId", "steps"}:
            raise invalid()
        snapshot, steps = body["snapshotId"], body["steps"]
        if (not isinstance(snapshot, str) or not SNAPSHOT_RE.fullmatch(snapshot)
                or not isinstance(steps, list) or not 1 <= len(steps) <= MAX_INPUT_BATCH):
            raise invalid()
        for step in steps:
            if not isinstance(step, dict):
                raise invalid()
            kind = step.get("action")
            if kind not in ("tap", "type") or "snapshotId" in step:
                raise invalid()
            simulator_input({**step, "action": "tapElement" if kind == "tap" else "typeInto",
                             "snapshotId": snapshot})
        return ["batch", "--agent"]
    schemas = {
        "tap": (["tap"], {"x": "-x", "y": "-y"}, {"hold": "--hold", "count": "--count"}),
        "swipe": (["swipe"], {"x": "--start-x", "y": "--start-y", "endX": "--end-x", "endY": "--end-y"}, {"duration": "--duration"}),
        "drag": (["drag"], {"x": "--start-x", "y": "--start-y", "endX": "--end-x", "endY": "--end-y"}, {"duration": "--duration", "hold": "--hold"}),
        "pinch": (["gesture", "pinch"], {"scale": "--scale"}, {"x": "-x", "y": "-y", "radius": "--radius"}),
        "rotate": (["gesture", "rotate"], {"x": "-x", "y": "-y", "radius": "--radius", "degrees": "--degrees"}, {}),
        "describe": (["describe-ui"], {}, {}),
        "displays": (["displays"], {}, {}),
        "button": (["button"], {"button": None}, {"duration": "--duration"}),
        "key": (["key"], {"code": None}, {"duration": "--duration"}),
        "type": (["type"], {"text": None}, {}),
        "snapshot": (["describe-ui", "--agent"], {}, {
            "snapshotId": "--snapshot-id", "offset": "--row-offset", "limit": "--row-limit",
        }),
        "tapElement": (["tap", "--agent"], {"snapshotId": "--snapshot-id", "ref": "--ref"}, {}),
        "tapMatching": (["tap", "--agent"], {}, {"identifier": "--id", "label": "--label"}),
        "holdElement": (["touch", "--agent", "--down", "--up"], {
            "snapshotId": "--snapshot-id", "ref": "--ref", "hold": "--delay",
        }, {}),
        "scrollElement": (["swipe", "--agent"], {
            "snapshotId": "--snapshot-id", "ref": "--ref", "direction": "--direction",
        }, {"distance": "--distance", "duration": "--duration"}),
        "typeInto": (["type", "--agent", "--stdin"], {
            "snapshotId": "--snapshot-id", "ref": "--ref", "text": None,
        }, {"focus": "--focus"}),
        "waitFor": (["describe-ui", "--agent"], {"condition": None}, {"timeout": None}),
        "clipboardCopy": ([], {"text": None}, {}),
        "keyCombo": (["key-combo"], {"modifiers": "--modifiers", "code": "--key"}, {}),
        "gesture": (["gesture"], {"preset": None}, {"duration": "--duration"}),
        "appearance": ([], {"style": None}, {}),
        "contentSize": ([], {"size": None}, {}),
        "preview": ([], {}, {"sinceFrameId": None}),
    }
    if action not in schemas:
        raise invalid()
    command, required, optional = schemas[action]
    keys = set(body) - {"action"}
    if not set(required) <= keys <= set(required) | set(optional):
        raise invalid()
    if action == "pinch" and ("x" in keys) != ("y" in keys):
        raise invalid()
    if action == "snapshot" and "offset" in keys and "snapshotId" not in keys:
        raise invalid()
    if action == "tapMatching" and len(keys) != 1:
        raise invalid()
    ranges = {"hold": (0.01, 10), "duration": (0.01, 10), "radius": (1, 4096),
              "scale": (0.1, 10), "degrees": (-360, 360), "count": (1, 2), "code": (0, 255),
              "offset": (0, 12288), "limit": (1, 64), "timeout": (1, 20), "distance": (0.05, 1)}
    integer_keys = {"count", "code", "offset", "limit", "timeout"}
    for key, flag in {**required, **optional}.items():
        if key not in body:
            continue
        value = body[key]
        if key == "button":
            if value not in ("home", "lock", "side-button", "siri", "apple-pay"):
                raise invalid()
        elif key == "text":
            if not isinstance(value, str) or not value or "\x00" in value:
                raise invalid()
            if action == "clipboardCopy":
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise invalid() from exc
                if len(encoded) > 8192:
                    raise invalid()
            elif len(value) > 256 or any(
                    not (32 <= ord(char) <= 126 or char in "\n\t") for char in value):
                raise invalid()
            continue
        elif key in ("snapshotId", "ref"):
            pattern = SNAPSHOT_RE if key == "snapshotId" else ELEMENT_REF_RE
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise invalid()
        elif key == "sinceFrameId":
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise invalid()
            continue
        elif key == "focus":
            if type(value) is not bool:
                raise invalid()
            if value:
                command.append(flag)
            continue
        elif key == "preset":
            if not isinstance(value, str) or value not in GESTURE_PRESETS:
                raise invalid()
        elif key == "direction":
            if value not in ("up", "down", "left", "right"):
                raise invalid()
        elif key == "style":
            if value not in ("light", "dark"):
                raise invalid()
        elif key == "size":
            if not isinstance(value, str) or value not in CONTENT_SIZES:
                raise invalid()
        elif key in ("identifier", "label"):
            if not isinstance(value, str) or not 1 <= len(value) <= 256 or not value.isprintable() or not value.strip():
                raise invalid()
            command.append(f"{flag}={value}")
            continue
        elif key == "modifiers":
            if (not isinstance(value, list) or not 1 <= len(value) <= 4
                    or any(type(code) is not int or not 224 <= code <= 231 for code in value)
                    or len(set(value)) != len(value)):
                raise invalid()
            value = ",".join(map(str, value))
        elif key == "condition":
            if value not in ("keyboardVisible", "settled"):
                raise invalid()
            continue
        else:
            low, high = ranges.get(key, (0, 8192))
            if type(value) not in (int, float) or not low <= value <= high or not math.isfinite(value):
                raise invalid()
            if (key in integer_keys and type(value) is not int) or (key == "scale" and value == 1):
                raise invalid()
            if key == "timeout":
                continue
        if flag:
            command.append(flag)
        command.append(str(value))
    return command


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
