"""API process for the iosagent worker.

This process runs as the unprivileged iosbroker account. It is not root and
it is not the personal login. The token stays in that account's home.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CODE_ROOT = str(Path(__file__).resolve().parent)
if _CODE_ROOT not in sys.path:
    sys.path.insert(0, _CODE_ROOT)

import ipaddress
import json
import os
import pwd
import subprocess
import threading

from api import App, serve
from config import BROKER_DIR, TAILSCALE_NET, load_broker_config, validate_listen
from containment import LIBRARY_ROOT, TEMP_ROOT, apply_rlimits, directory_size, install_import_path, launch_path_problems
from memory import sample_system
from runner import SudoRunner
from scheduler import Scheduler

install_import_path()


def make_app(cfg):
    token = cfg.token_file.read_text().strip()
    if len(token) < 16:
        raise SystemExit("token file is missing or too short")
    runner = SudoRunner(cfg.worker.device_allowlist, cfg.worker.device_denylist)
    default_device = sorted(cfg.worker.device_allowlist)[0]
    roots = [cfg.worker.workspace_root, cfg.worker.spool_root, cfg.worker.artifact_root, TEMP_ROOT]
    disk_used = lambda: directory_size(roots)
    scheduler = Scheduler(
        runner,
        sample_system,
        allowlist=cfg.worker.device_allowlist,
        denylist=cfg.worker.device_denylist,
        default_device=default_device,
        clock=lambda: __import__("time").monotonic(),
        artifact_root=cfg.worker.artifact_root,
        max_running=cfg.max_running_jobs,
        max_build_jobs=cfg.max_build_jobs,
        idle_seconds=cfg.idle_seconds,
        disk_used=disk_used,
        disk_budget=cfg.worker.disk_budget,
    )
    app = App(
        scheduler,
        token,
        cfg.worker.spool_root,
        cfg.allow_loopback,
        cfg.worker.max_upload_bytes,
        disk_used=disk_used,
        disk_budget=cfg.worker.disk_budget,
    )
    return app, scheduler


def listen_host(cfg) -> str:
    host = tailscale_ipv4() if cfg.listen_host == "tailscale" else cfg.listen_host
    validate_listen(host, cfg.allow_loopback)
    return host


def tailscale_ipv4() -> str:
    """Read the CGNAT address from the interface table.

    The Tailscale CLI is tied to the console user's GUI session. The broker
    account cannot use it, and it must not listen on any other interface.
    """
    completed = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=5, check=False)
    found: list[str] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "inet":
            continue
        try:
            address = ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        if address in TAILSCALE_NET and str(address) not in found:
            found.append(str(address))
    if len(found) != 1:
        raise SystemExit("Refusing to listen without exactly one Tailscale address.")
    return found[0]


def require_broker_account() -> None:
    if os.environ.get("IOS_WORKER_DEV") == "1":
        return
    if os.geteuid() == 0:
        raise SystemExit("refusing to run the API as root")
    try:
        account = pwd.getpwnam("iosbroker")
    except KeyError as exc:
        raise SystemExit("iosbroker is missing. Run install_system.py as root.") from exc
    if os.geteuid() != account.pw_uid:
        raise SystemExit("the broker must run as iosbroker")


def main(argv: list[str]) -> int:
    os.umask(0o077)
    require_broker_account()
    if os.environ.get("IOS_WORKER_DEV") != "1":
        apply_rlimits()
    if Path(__file__).resolve().parent == LIBRARY_ROOT:
        problems = launch_path_problems(LIBRARY_ROOT)
        if problems:
            sys.stderr.write("refusing to start; launch path is writable\n")
            for item in problems:
                sys.stderr.write(item + "\n")
            return 1
    if len(argv) > 1 and argv[1] == "audit":
        from audit import collect

        json.dump(collect(), sys.stdout, indent=2)
        print()
        return 0
    config_path = Path(argv[1]) if len(argv) > 1 else BROKER_DIR / "broker.json"
    cfg = load_broker_config(config_path)
    host = listen_host(cfg)
    app, scheduler = make_app(cfg)
    stop = threading.Event()
    threading.Thread(target=scheduler.run_forever, args=(stop,), daemon=True).start()
    httpd = serve(app, host, cfg.listen_port)
    print(
        f"listening on {host}:{cfg.listen_port} as uid {os.geteuid()}. "
        "Build scripts run as iosagent. The token is not in that account.",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
