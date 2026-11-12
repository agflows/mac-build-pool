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

import hmac
import ipaddress
import json
import os
import pwd
import stat
import subprocess
import threading

from api import App, serve
from config import BROKER_DIR, TAILSCALE_NET, load_broker_config, validate_listen
from containment import LIBRARY_ROOT, TEMP_ROOT, apply_rlimits, directory_size, install_import_path, launch_path_problems
from memory import sample_system
from isolated_runner import IsolatedRunner
from execution_policy import execution_mode, NATIVE, require_native_config, require_protected_file
from native_runner import NativeUserRunner
from policy import PolicyError
from vm_runner import TartRunner, CONFIG as VM_CONFIG
from scheduler import Scheduler

install_import_path()

PEER_TRIAL_CONFIG = LIBRARY_ROOT / "peer-trial.json"


def _read_secret(path: Path, label: str) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SystemExit(label + " file is missing") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(label + " file must not be a symlink")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit(label + " file must be readable only by its owner")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_ino != info.st_ino or current.st_dev != info.st_dev:
            raise SystemExit(label + " file must not be a symlink")
        token = os.read(fd, 256).decode("utf-8").strip()
    finally:
        os.close(fd)
    if len(token) < 16 or "\n" in token or "\x00" in token:
        raise SystemExit(label + " file is missing or too short")
    return token


def make_app(cfg):
    token = _read_secret(cfg.token_file, "token")
    operator_token = _read_secret(cfg.operator_token_file, "operator token")
    if hmac.compare_digest(token.encode(), operator_token.encode()):
        raise SystemExit("operator token must be different from the agent token")
    mode = execution_mode()
    if mode == NATIVE:
        require_native_config(cfg.worker)
    runner_class = NativeUserRunner if mode == NATIVE else IsolatedRunner
    runner = (TartRunner(cfg.worker.device_allowlist,cfg.worker.device_denylist,cfg.worker,
                        validation_mode=cfg.allow_loopback and cfg.listen_host=='127.0.0.1')
              if mode != NATIVE and VM_CONFIG.exists() else
              runner_class(cfg.worker.device_allowlist, cfg.worker.device_denylist))
    default_device = sorted(cfg.worker.device_allowlist)[0]
    roots = [cfg.worker.workspace_root, cfg.worker.spool_root, cfg.worker.artifact_root, TEMP_ROOT]
    export_root = cfg.worker.artifact_root.parent / "export"
    export_root.mkdir(mode=0o700, exist_ok=True)
    roots.append(export_root)
    disk_used = lambda: directory_size(roots)
    scheduler = Scheduler(
        runner,
        sample_system,
        allowlist=cfg.worker.device_allowlist,
        denylist=cfg.worker.device_denylist,
        default_device=default_device,
        clock=lambda: __import__("time").monotonic(),
        artifact_root=cfg.worker.artifact_root,
        export_root=export_root,
        max_running=cfg.max_running_jobs,
        max_build_jobs=cfg.max_build_jobs,
        idle_seconds=cfg.idle_seconds,
        disk_used=disk_used,
        disk_budget=cfg.worker.disk_budget,
    )
    app = App(
        scheduler,
        token,
        operator_token,
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


def agent_instructions(cfg, app, runner, *, trial_peer=None) -> str:
    if runner.validation_mode:
        cfg = load_broker_config(BROKER_DIR / "broker.json")
        token = _read_secret(cfg.token_file, "agent token")
    else:
        token = app.token
    host = listen_host(cfg)
    if ipaddress.ip_address(host) not in TAILSCALE_NET:
        raise ValueError("Agent instructions require a Tailscale address")
    state = "Remote jobs are disabled. Wait for the owner to enable them."
    if trial_peer is not None and runner.installed():
        state = f"Remote trial jobs are enabled for {trial_peer}."
    elif not runner.validation_mode and runner.installed():
        state = "Remote jobs are enabled."
    return "\n".join((
        "Use agflows/mac-build-pool from a machine on the same Tailscale network.",
        f"IOS_WORKER_URL=http://{host}:{cfg.listen_port}",
        f"Agent bearer token: {token}",
        state,
        "Save the token in a private file (mode 600) and set IOS_WORKER_TOKEN_FILE to its path.",
        "Run python3 cli.py health first. Use one lease per session, renew it while working, and release it when done.",
    ))


def load_trial_peer(path: Path) -> str:
    require_protected_file(path)
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) != {"peer"} or not isinstance(data["peer"], str):
        raise SystemExit("The trial requires exactly one owner-approved Tailscale peer.")
    try:
        peer = ipaddress.IPv4Address(data["peer"])
    except ipaddress.AddressValueError as exc:
        raise SystemExit("The trial peer must have a Tailscale IPv4 address.") from exc
    if peer not in TAILSCALE_NET:
        raise SystemExit("The trial peer must have a Tailscale IPv4 address.")
    return str(peer)


def start_peer_trial(app, scheduler, peer):
    runner = scheduler.runner
    if not isinstance(runner, TartRunner) or not runner.validation_mode or not runner.installed():
        raise SystemExit("The peer trial requires the installed isolated validation worker.")
    cfg = load_broker_config(BROKER_DIR / "broker.json")
    host = listen_host(cfg)
    validate_listen(host, allow_loopback=False)
    token = _read_secret(cfg.token_file, "agent token")
    if hmac.compare_digest(token.encode(), app.operator_token.encode()):
        raise SystemExit("The agent token must be different from the validation operator token.")
    peer_app = App(
        scheduler,
        token,
        app.operator_token,
        app.spool_root,
        False,
        app.max_upload_bytes,
        disk_used=app.disk_used,
        disk_budget=app.disk_budget,
        trial_peer=peer,
    )
    httpd = serve(peer_app, host, cfg.listen_port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"Isolated trial listening on {host}:{cfg.listen_port} for {peer}.", flush=True)
    return httpd


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
    trial_peer = None
    if len(argv) > 2:
        if argv[2:] != ["--peer-trial"] or config_path != BROKER_DIR / "validation.json":
            raise SystemExit("Peer trial is available only with the installed validation configuration.")
        trial_peer = load_trial_peer(PEER_TRIAL_CONFIG)
    cfg = load_broker_config(config_path)
    host = listen_host(cfg)
    app, scheduler = make_app(cfg)
    with serve(app, host, cfg.listen_port) as httpd:
        peer_httpd = start_peer_trial(app, scheduler, trial_peer) if trial_peer is not None else None
        stop = threading.Event()
        try:
            if getattr(scheduler.runner, 'vm_backend', False):
                from owner_menu import start as start_owner_menu
                try:
                    start_owner_menu(
                        scheduler,
                        validation=scheduler.runner.validation_mode,
                        instructions=lambda: agent_instructions(cfg, app, scheduler.runner, trial_peer=trial_peer),
                    )
                except (OSError, ValueError, KeyError, PolicyError) as exc:
                    sys.stderr.write(f"Owner menu unavailable: {type(exc).__name__}\n")
            threading.Thread(target=scheduler.run_forever, args=(stop,), daemon=True).start()
            print(
                f"listening on {host}:{cfg.listen_port} as uid {os.geteuid()}. "
                f"Execution mode: {getattr(scheduler.runner, 'execution_mode', 'isolated-only')}. No automatic backend fallback.",
                flush=True,
            )
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            if peer_httpd is not None:
                peer_httpd.shutdown()
                peer_httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
