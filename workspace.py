"""Trusted-project preparation helpers. This is NOT a filesystem/network sandbox.

Only the owner can enable dependency scripts and choose toolchain paths. All
operations run after dropping to iosagent. HOME/cache/TMPDIR isolation prevents
accidental cross-project configuration; it is not a boundary against hostile code.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from containment import worker_child_env
from policy import PolicyError, require_public_env, require_under, require_recipe

TOOLCHAIN_KEYS = {
    "expo-ios": frozenset({"node", "pod", "ruby_bin"}),
    "flutter-ios": frozenset({"flutter_sdk", "pod", "ruby_bin"}),
    "swift-ios": frozenset(),
}


def require_preparation_enabled(cfg) -> None:
    if cfg.sandbox_builds:
        raise PolicyError("sandbox_untested", "Dependency/build sandboxing is not validated; refusing execution.")
    if not cfg.allow_dependency_install:
        raise PolicyError("preparation_disabled", "Owner must explicitly enable trusted-project dependency installation in worker.json.")


def toolchain_paths(cfg, recipe: str = "expo-ios") -> dict[str, Path]:
    require_preparation_enabled(cfg)
    required = TOOLCHAIN_KEYS[require_recipe(recipe)]
    if recipe == "expo-ios":
        required = required | (cfg.toolchain.keys() & {"npm_cli", "bun"})
    if not required.issubset(cfg.toolchain):
        raise PolicyError("toolchain_missing", "Configure the recipe's approved toolchain in the guest's owner-managed worker.json.")
    paths = {}
    for name in sorted(required):
        value = cfg.toolchain[name]
        path = Path(value)
        if not path.is_absolute():
            raise PolicyError("bad_config", "Toolchain paths must be absolute.")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise PolicyError("toolchain_missing", f"Approved toolchain entry is missing: {name}") from exc
        if not (resolved.is_dir() if name in {"ruby_bin", "flutter_sdk"} else resolved.is_file()):
            raise PolicyError("toolchain_missing", f"Invalid toolchain entry: {name}")
        # Executed as iosagent: access() accounts for that account's ACLs/groups.
        # Check both symlink locations and resolved ancestors (e.g. Homebrew Cellar).
        for item in {path, resolved, *path.parents, *resolved.parents}:
            if os.access(item, os.W_OK):
                raise PolicyError("toolchain_writable", f"Toolchain entry or ancestor is writable by iosagent: {name}")
        if name in {"node", "bun", "pod", "ruby_bin", "flutter_sdk"} and not os.access(resolved, os.X_OK):
            raise PolicyError("toolchain_missing", f"Toolchain entry is not executable: {name}")
        paths[name] = path
    return paths


def is_expo_project(revision: Path) -> bool:
    package = revision / "package.json"
    if not package.is_file():
        return False
    require_under(package, revision)
    data = json.loads(package.read_text())
    return "expo" in data.get("dependencies", {}) or "expo" in data.get("devDependencies", {})


def is_flutter_project(revision: Path) -> bool:
    return (revision / "pubspec.yaml").is_file()


def copy_flutter_sdk(revision: Path, source: Path) -> Path:
    """Use a disposable SDK copy: Flutter writes its cache/lock even for builds."""
    source = source.resolve(strict=True)
    destination = local_directory(revision, ".worker") / "flutter"
    if destination.exists() or destination.is_symlink():
        raise PolicyError("preparation_required", "Use a fresh source revision for Flutter preparation; SDK copy already exists.")
    links = {}
    for item in source.rglob("*"):
        if item.is_symlink():
            target = require_under(item, source)
            links[item.relative_to(source)] = target.relative_to(source)
    shutil.copytree(source, destination, symlinks=True)
    # Rebase absolute links to the private copy; never let Flutter mutate the base SDK.
    for relative, target in links.items():
        link = destination / relative
        link.unlink()
        link.symlink_to(os.path.relpath(destination / target, link.parent))
    return destination


def local_directory(revision: Path, relative: str) -> Path:
    """Refuse preexisting links before creating job-local mutable directories."""
    path = revision
    for component in Path(relative).parts:
        path = path / component
        if path.is_symlink():
            raise PolicyError("path_escape", "Job-local directories must not be symlinks.")
        require_under(path, revision)
        path.mkdir(mode=0o700, exist_ok=True)
    return path


def workspace_env(revision: Path, cfg, public_env: dict | None = None, *, tools=None) -> dict[str, str]:
    tools = toolchain_paths(cfg) if tools is None else tools
    env = worker_child_env(cfg.developer_dir)
    home = local_directory(revision, ".worker/home")
    cache = local_directory(revision, ".worker/cache")
    tmp = local_directory(revision, ".worker/tmp")
    node_cache = local_directory(revision, ".worker/cache/node")
    env.update({
        "HOME": str(home),
        "CFFIXED_USER_HOME": str(home),
        "TMPDIR": str(tmp) + "/",
        "XDG_CACHE_HOME": str(cache),
        "CLANG_MODULE_CACHE_PATH": str(cache / "clang"),
        "MODULE_CACHE_DIR": str(cache / "clang"),
        "PATH": ":".join(dict.fromkeys(
            ([str(tools["node"].parent)] if "node" in tools else []) +
            ([str(tools["bun"].parent)] if "bun" in tools else []) +
            ([str(tools["ruby_bin"]), str(tools["pod"].parent)] if "pod" in tools else []) +
            ([str(revision / ".worker/flutter/bin")] if "flutter_sdk" in tools else []) +
            ["/usr/bin", "/bin", "/usr/sbin", "/sbin"])),
        "PUB_CACHE": str(cache / "pub"),
        "npm_config_cache": str(node_cache),
        "npm_config_prefix": str(home / "npm-global"),
        "npm_config_userconfig": str(home / ".npmrc"),
        "npm_config_globalconfig": str(home / "global.npmrc"),
        "BUN_INSTALL_CACHE_DIR": str(cache / "bun"),
        "BUN_CONFIG_MAX_HTTP_REQUESTS": "8",
        "npm_config_maxsockets": "8",
        "CP_HOME_DIR": str(cache / "cocoapods-home"),
        "CP_CACHE_DIR": str(cache / "cocoapods"),
        "BUNDLE_USER_HOME": str(home / ".bundle"),
        "CI": "1",
        "EXPO_NO_DOTENV": "1",
        "EXPO_NO_TELEMETRY": "1",
        "COCOAPODS_DISABLE_STATS": "true",
        "LANG": "en_US.UTF-8",
    })
    if "node" in tools:
        env["NODE_BINARY"] = str(tools["node"])
    if getattr(cfg, "package_proxy", False):
        env["NODE_USE_ENV_PROXY"] = "1"
        env['NODE_EXTRA_CA_CERTS']='/Library/ios-worker/proxy-ca.pem'
        for key in ('SSL_CERT_FILE','CURL_CA_BUNDLE','GIT_SSL_CAINFO'):
            env[key]='/Library/ios-worker/proxy-ca-bundle.pem'
        for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            env[key] = "http://127.0.0.1:18741"
        env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1,::1"
    if "flutter_sdk" in tools:
        env["FLUTTER_ROOT"] = str(revision / ".worker/flutter")
        env["FLUTTER_SUPPRESS_ANALYTICS"] = "true"
        env["DART_SUPPRESS_ANALYTICS"] = "true"
    env.update(require_public_env(public_env or {}))
    return env


def preparation_receipt(revision: Path) -> Path:
    return local_directory(revision, ".worker") / "prepared.json"


def load_prepared_env(revision: Path, cfg) -> dict[str, str]:
    receipt = preparation_receipt(revision)
    if receipt.is_symlink() or not receipt.is_file():
        raise PolicyError("preparation_required", "Run the project's preparation job successfully before building.")
    data = json.loads(receipt.read_text())
    tools = toolchain_paths(cfg, require_recipe(data.get("recipe")))
    return workspace_env(revision, cfg, require_public_env(data.get("publicEnv", {})), tools=tools)
