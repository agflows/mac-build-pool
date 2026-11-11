# Native-user preparation evidence — 2026-11-11

Base: main at `c3b3d53` (agflows/mac-build-pool). The owner changed the requested
boundary to account separation and explicitly requested code only, leaving the
service unchanged. This report is not deployment or isolation acceptance.

## Executed checks

Host: Apple M1 arm64, macOS 26.5 (25F71), 16 GB RAM. Xcode developer directory
was `/Applications/Xcode.app/Contents/Developer`.

- `/usr/bin/python3 -m unittest discover -s tests -v`: **112 tests passed**,
  7.481 seconds. [Full output](2026-11-11-native-tests.txt).
- `/usr/bin/clang -O2 -Wall -Werror -o /private/tmp/mac-build-pool-worker-cap-check worker_cap.c`:
  exit 0. This compiles the trusted launcher only; the resulting binary was
  not executed or installed.
- `git diff --check`: passed.

Initial baseline: 95 tests, four macOS-specific failures comparing `/var` and
`/private/var` temporary paths. Canonicalizing the fixture root fixed those
assertions. Review also caught an unavailable `closefrom` function; descriptor
cleanup now uses macOS `getdtablesize` and compilation passes.

Tests cover policy default/explicit acknowledgement, unprotected policy and
symlink rejection, writable ACL/failed inspection rejection, wrong account/admin
rejection, fixed data roots, policy revocation, missing launcher, personal simulator
denial, malformed helper success, installer flags and ACL plan, honest health
reporting, unavailable-backend HTTP 503 before upload staging, and absent signing,
deployment, USB and mode-switch routes. Existing archive, artifact, authorization,
resource and recipe regressions also pass.

Tests use temporary files, loopback HTTP servers and mocked worker/system calls.
Account/ACL installer tests validate intended calls, not actual installed macOS
permissions. Socket tests ran outside the tool filesystem restrictions to permit
local loopback listeners; they did not contact or modify the installed broker.

## Explicitly not performed

No installer, launchctl mutation, account/ACL changes, sudoers installation, VM,
network-rule modification, credential access, project builds, simulator launch,
screenshot, signing or USB operation. The installed broker's runtime state and
security properties are not certified by this report.

Real Swift, Expo/Couple Joy and Flutter builds and returned screenshots remain
unvalidated. So do installed-account file-denial tests and resource behavior.
The isolated VM/network controller remains unimplemented. Native mode intentionally
does not claim network isolation or a disposable filesystem. See
[Native user mode](../NATIVE_USER_MODE.md) before any future deployment.
