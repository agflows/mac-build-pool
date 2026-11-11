"""Paths and limits. The token file is named here and never copied into the worker config."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

from containment import DISK_BUDGET, MEMORY_LIMIT
from policy import PolicyError, normalize_udid

TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")
DEVELOPER_DIR = "/Applications/Xcode.app/Contents/Developer"
LIBRARY_ROOT = Path("/Library/ios-worker")
BROKER_DIR = Path("/Users/iosbroker/.ios-worker")
DATA_ROOT = LIBRARY_ROOT / "data"


@dataclass
class WorkerConfig:
    workspace_root: Path
    spool_root: Path
    artifact_root: Path
    developer_dir: str
    device_allowlist: set[str]
    device_denylist: set[str]
    sandbox_builds: bool = False
    max_upload_bytes: int = 64 * 1024 * 1024
    disk_budget: int = DISK_BUDGET
    memory_limit: int = MEMORY_LIMIT


@dataclass
class BrokerConfig:
    worker: WorkerConfig
    listen_host: str
    listen_port: int
    token_file: Path
    idle_seconds: float = 600.0
    max_running_jobs: int = 1
    max_build_jobs: int = 2
    allow_loopback: bool = False


def load_worker_config(path: Path) -> WorkerConfig:
    data = json.loads(path.read_text())
    if "token" in data or "token_file" in data:
        raise PolicyError("bad_config", "worker config must not contain a token.")
    developer = data.get("developer_dir", DEVELOPER_DIR)
    if developer != DEVELOPER_DIR:
        raise PolicyError("bad_config", "developer_dir is fixed to the Xcode.app toolchain.")
    allow = {normalize_udid(item) for item in data.get("device_allowlist", [])}
    deny = {normalize_udid(item) for item in data.get("device_denylist", [])}
    if not allow:
        raise PolicyError("bad_config", "device_allowlist is empty.")
    return WorkerConfig(
        workspace_root=Path(data["workspace_root"]),
        spool_root=Path(data["spool_root"]),
        artifact_root=Path(data["artifact_root"]),
        developer_dir=developer,
        device_allowlist=allow,
        device_denylist=deny,
        sandbox_builds=bool(data.get("sandbox_builds", False)),
        max_upload_bytes=min(int(data.get("max_upload_bytes", 64 * 1024 * 1024)), 64 * 1024 * 1024),
        disk_budget=min(int(data.get("disk_budget_bytes", DISK_BUDGET)), DISK_BUDGET),
        memory_limit=min(int(data.get("memory_limit_bytes", MEMORY_LIMIT)), MEMORY_LIMIT),
    )


def load_broker_config(path: Path) -> BrokerConfig:
    data = json.loads(path.read_text())
    return BrokerConfig(
        worker=load_worker_config(Path(data["worker_config"])),
        listen_host=str(data["listen_host"]),
        listen_port=int(data.get("listen_port", 8741)),
        token_file=Path(data.get("token_file", str(BROKER_DIR / "token"))),
        idle_seconds=float(data.get("simulator_idle_seconds", 600)),
        max_running_jobs=int(data.get("max_running_jobs", 1)),
        max_build_jobs=int(data.get("max_build_jobs", 2)),
        allow_loopback=bool(data.get("allow_loopback", False)),
    )


def validate_listen(host: str, allow_loopback: bool) -> None:
    if host in {"0.0.0.0", "::", ""}:
        raise PolicyError("bad_listen", "Refusing to listen on every interface.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise PolicyError("bad_listen", "Listen address must be a Tailscale IP.") from exc
    if address.is_loopback:
        if not allow_loopback:
            raise PolicyError("bad_listen", "Refusing a loopback listener.")
        return
    if address not in TAILSCALE_NET:
        raise PolicyError("bad_listen", "Listen address is not in the Tailscale CGNAT range.")


def peer_allowed(host: str, allow_loopback: bool) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_loopback:
        return allow_loopback
    return address in TAILSCALE_NET
