# Explicit native user mode (prepared, not deployed)

On 2026-11-11 the owner rejected a full VM, accepted separate-user execution,
and instructed: **“Keep service unchanged; prepare code only.”** This document
records that revised scope. No installer, service restart, project build,
simulator launch, signing, or USB deployment was performed in this pass.

## Boundary and limitations

The broker runs as iosbroker. The fixed privileged launcher permanently drops
to the dedicated, non-admin iosagent account before running worker Python.
Projects never run as the personal login account. The worker account must have
its own `/Users/iosagent` home. No personal keychain or signing credentials are
provisioned. No signing, device deployment, or USB API is added.

This is **account separation, not full isolation**. Project scripts can use the
worker account's ordinary network access, including host/LAN/tailnet services,
and read host files that filesystem permissions allow. Jobs share one worker
account and can affect later jobs. Resource checks and per-process limits are
not a hard aggregate memory or disk quota. Disabling API routes does not prove
hardware isolation from arbitrary project code. Native mode cannot satisfy the
stronger threat model in ISOLATION_CONTRACT.md. No network protection was installed
or validated here, and no existing network rules were changed.

## Explicit selection, no fallback

A missing `/Library/ios-worker/execution.json` means `isolated-only`. That mode
still requires the external controller and the guest guard. It never falls back
to native execution. No API request, environment variable, broker setting, or
worker setting can opt in to native execution.

Native mode requires a root-controlled policy file containing:

```json
{"mode":"native-user","acknowledgement":"I accept account separation without VM or network isolation."}
```

The broker checks policy, helper, protected modules, and configuration. The
worker rechecks policy and its real/effective account before processing requests.
Native operations recheck authorization, so removing policy prevents subsequent
operations; it does not terminate already running jobs. Changing backend requires
a planned restart. Invalid policy fails closed. Health reports `unix-account`,
`networkIsolationVerified: false`, and disabled signing/USB API flags.
`executorInstalled` is a prerequisite check, **not acceptance-test evidence**.

Native data roots are fixed under `/Library/ios-worker/data`. Only work,
artifacts, and temporary directories receive worker write ACLs. Spool access is
read-only. Exports and broker credentials receive no worker grants. Source archive
validation, simulator allow/deny lists (including the personal simulator deny),
fixed command routing, sanitized environment, private export checks, and operator
resource approvals remain. `sandbox_builds: true` still refuses execution; this
change does not pretend that an unvalidated native sandbox works.

## Future installation, not authorized in this pass

The installer defaults to `isolated-only` and removes the native launcher grant.
A future maintenance window must explicitly choose both flags:

```sh
sudo /usr/bin/python3 /path/to/reviewed/mac-build-pool/install_system.py \
  /path/to/reviewed/mac-build-pool \
  --execution-mode native-user --accept-native-risk
```

**This command changes and restarts the service; it was not run.** Before using
it, drain jobs and obtain maintenance approval, review existing account memberships,
private homes and ACLs, verify protected worker/toolchain paths, available disk,
and memory pressure. The native installer requires an existing non-admin iosagent
account and private home. It compiles the fixed launcher and validates its exact
no-argument sudo grant before stopping the service. It does not provision personal
credentials. Dependency installation still requires its separate owner config opt-in.

After installation, test access denial to broker credentials and personal private
files as iosagent, writable-code rejection, archive/export escapes, personal
simulator denial, and missing-helper/policy failures. Network denial must **not**
be claimed for this mode. Validate actual Swift, the approved Couple Joy Expo
snapshot, and Flutter builds, launches, and returned screenshots with the worker
simulator only. Those tests remain outstanding. Do not build these projects under
the main account to work around worker failures.

Signing/device access remains a separate future signer/deployer with explicit
owner approval per artifact and device; see SIGNING_AND_DEVICES.md.
