# Local Mac agent handoff

> **Owner update, 2026-11-11:** The owner subsequently accepted separate-user
> execution and requested **code preparation only; keep the service unchanged**.
> See [Native user mode](NATIVE_USER_MODE.md) for that explicit opt-in path.
> The VM requirements below continue to apply to `isolated-only`, not to the
> weaker native mode. Signing and USB APIs remain disabled in both modes.

## Read first: this is not a ready isolated worker

Repository: https://github.com/agflows/mac-build-pool. Pull the updated code and
read README.md, ISOLATION_CONTRACT.md and SIGNING_AND_DEVICES.md fully.

The owner clarified a strict requirement: a controlled cloud agent may build
Swift, Expo and Flutter apps but must not gain access to personal documents,
host environment or local/tailnet/VPN networks. Do not relax this to make a build
pass. A separate Unix account alone does not provide this boundary.

**The VM/network controller is missing.** The host now uses IsolatedRunner and
fails jobs with `isolation_required` unless a protected
`/Library/ios-worker/isolation-executor` exists. That is an interface for a real
controller, not something to satisfy with an echo script or native-host wrapper.
The executor-side worker refuses a physical Mac even in IOS_WORKER_DEV mode.
Linux tests verify logic/no-fallback, not native builds or isolation.

Your task is to implement/provision and verify that missing boundary on the Mac,
then validate/fix all three framework workflows. Keep code changes in this repo,
add tests, and push fixes. Do not leave only hotfixes under /Library.

## Existing machine and last test (verify current state)

- MacBook Pro M1, 8 cores, 16 GB RAM; owner uses it interactively.
- Xcode reported as 26.6 at `/Applications/Xcode.app/Contents/Developer`.
- Original headless account: iosagent, previously UID 504, non-admin. It could
  build a native sample, run its simulator/XCTest and capture a screenshot without
  a graphical login. This demonstrated compatibility, **not the required isolation**.
- Broker account: iosbroker. Service: `system/com.iosworker.broker`.
- Code `/Library/ios-worker`; root-owned worker.json there.
- Broker config `/Users/iosbroker/.ios-worker/broker.json`.
- Agent/operator token files in that broker directory, respectively `token` and
  `operator-token`, both 600. Never print or commit values, copy operator credentials
  to the cloud, or use the agent token to authorize deployment/resource overrides.
- Old API bound to Mac Tailscale address `100.114.181.78:8741`.
- Old worker simulator `3C8BB98E-6383-446B-AF87-1E1282762A13`.
- Personal simulator `4D015300-4BAE-4E6D-89C9-BC4D454E4216`: NEVER touch it.
  New isolated guests need their own simulator IDs and controller-owned mappings.
- Last observed pressure: warning. An 8 GB guest on this 16 GB laptop should be
  owner-approved/idle-only initially; don't silently reuse native-build admission
  that allowed work at warning. Don't kill the owner's simulator or other apps.

The VM `agents-noctem.tail3bcb9e.ts.net` authenticated to the old worker and submitted
the real Couple Joy app. Revision `1b0ecc980dde48df`, build `5014b378e7ea4710`, failed
with Xcode code 65: `[CP] Check Pods Manifest.lock`, missing CocoaPods installation.
This is not a macOS sandbox denial. Diagnostics returned correctly; no runnable app
or screenshot resulted. Lease was released; no running/queued jobs remained.

VM paths:
- `/home/leolurch/Documents/mac-build-pool`: code/client checkout.
- `/home/leolurch/Documents/b2c-org/mobile-app`: actual app source.
- `/home/leolurch/tmp/mac-build-pool-test/source.tar.gz`: previous safe snapshot,
  generated ios/ included but no node_modules/dotenv/private keys.
- Same test directory: remote-results.json and `5014b378e7ea4710.log`.
- `/home/leolurch/.config/mac-build-pool/token`: VM-side agent token, mode 600.

Ask the VM agent for a fresh snapshot or transfer it over an authorized channel.
Do not assume old job IDs survive broker restarts. The agent token appeared in a
chat previously; coordinate rotation with the owner/VM agent, never silently
break the client's access or print the replacement.

## Installation order and migration precautions

1. Audit active jobs/leases, current code and service permissions; arrange an owner-
   approved maintenance window. Do not overwrite/restart a busy worker.
2. Review the host installer changes. `install_system.py` now removes this project's
   old `/etc/sudoers.d/ios-worker` native grant and `/Library/ios-worker/worker_cap`.
   It also removes native job-account ACL access to host staging and no longer
   honors the old IOS_WORKER_DEV account-check bypass. It does NOT install a VM
   controller. Installing it without a controller
   deliberately stops project execution, although authenticated health still works.
   This is a breaking security migration, not a drop-in Expo fix.
3. Implement the controller contract before serving jobs. Choose/review a macOS VM
   backend, network enforcement and control channel. Do not assume NAT or default
   'public-only' networking blocks gateway/host services. Verify IPv6 and DNS paths.
   Do not join jobs to the entire tailnet or mount personal folders.
4. Provision an approved guest image with Xcode, simulator runtime, non-admin job
   account and immutable worker/toolchain files. No personal Apple ID, login sessions,
   signing keys, shared clipboard, home mounts, SSH agents or USB passthrough.
   For a first implementation, use Apple Virtualization guests recognized by the
   entry guard; validate the actual VirtualMac model instead of bypassing the guard.
5. Implement lease/VM lifecycle notifications, staging, mapping, export, cancellation,
   timeout/reboot cleanup and VM-level resource admission described in the contract.
   Those are not yet implemented by IsolatedRunner's JSON transport.
6. Complete the real negative security tests from the contract BEFORE permitting
   cloud jobs. Test from dependency scripts, build scripts, plugins, tests and apps,
   not only an interactive shell. Use canaries, not real credentials.
7. Only then install the reviewed controller as root-owned/non-writable. No shell,
   package-manager or broad interpreter sudo grants. Host broker remains iosbroker.
   A controller file's presence is not a security attestation; add explicit readiness
   and capability negotiation as part of the integration.
8. Install/upgrade the reviewed host broker with owner authorization from an absolute
   checkout path outside protected Documents. Use private, owner-controlled
   staging, not a world-writable shared checkout. The revised installer only
   stops its named service; it no longer deletes the old shared copy or kills
   arbitrary processes listening on port 8741.
   Run `/usr/bin/python3 -m unittest discover -s tests -v` as a regular user first.
   The installer preserves owner worker.json and tokens; review the new VM device
   mappings. Keep source/executable paths inaccessible to job modification.
9. Guest deployment is a separate task. Do NOT run the host installer inside the
   guest expecting it to configure the guest worker or an additional nested executor.
   Install the protected worker payload/config and account there explicitly. The
   legacy worker_cap/SudoRunner sources are references for guest-only privilege
   dropping if needed, not an invitation to restore host sudo permissions.

The owner has not authorized weakening the boundary. If the chosen backend cannot
satisfy it, report the blocker rather than changing the threat model or native
fallback behavior. FileVault unlock after reboot remains a physical-host requirement.

## Framework setup inside the guest

`allow_dependency_install` defaults to false. Enable it only in the **guest's**
root-owned worker.json after the guest boundary is validated. It is not an isolation
flag. Guest toolchain fields are owner paths, not cloud request values:

```json
{
  "allow_dependency_install": true,
  "toolchain": {
    "node": "/opt/homebrew/bin/node",
    "npm_cli": "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js",
    "pod": "/opt/homebrew/bin/pod",
    "ruby_bin": "/opt/homebrew/opt/ruby/bin",
    "flutter_sdk": "/Library/ios-worker/toolchains/flutter"
  }
}
```

Merge fields into the full config; don't replace roots/device IDs/limits. Paths are
examples. Provision actual versions and audit their imported libraries/ancestors.
Never run Homebrew as root or make base toolchains writable by the job account.
Swift needs none of these extra toolchain entries. Flutter needs pod/Ruby plus an
approved SDK; its job-private SDK copy permits its cache updates without modifying
the base. Account for SDK copy space and external downloads in VM budgets.

### Swift acceptance

Use an actual minimal SwiftUI/UIKit Xcode app. Test Debug and Release builds, launch
and screenshot; add a real XCTest target to test build-for-testing/test-without-
building. Also test a pinned Swift package via `swift-ios` preparation. Private
package credentials are not part of this implementation; don't forward host keys.

### Expo / actual Couple Joy acceptance

App: Expo `~58.0.23`, React Native `0.88.1`, bundle ID `app.ours.together`, expected
scheme `CoupleJoy`, npm lockfile. Read its AGENTS.md and matching Expo documentation
before changing config/plugins; do not patch generated iOS files as the solution.

1. Snapshot app-root source/config/assets/plugins/lockfile. Exclude .env, credentials,
   node_modules, .worker, .git and build products. Don't upload Linux node_modules.
2. Acquire a lease; ingest; prepare with recipe `expo-ios`. It runs npm ci, local
   Expo CLI prebuild (`--clean --no-install`), and pod install. Validate the exact
   Node/Ruby/Pod environment and stripped-environment behavior on this guest.
3. Supply only public runtime values through `publicEnv`: e.g.
   EXPO_PUBLIC_SUPABASE_URL and EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY. NEVER supply
   DB_PASSWORD or SUPABASE_SECRET_KEY. Public values are compiled into the app.
4. Build with scheme CoupleJoy, configuration Release, forTesting false and
   bootSimulator false. Release must actually embed JS; verify startup without Metro.
5. Launch with configuration Release in the guest. Honor operator resource approval.
   Retrieve/open actual PNG screenshots and verify app UI, not splash/error/demo.
6. Its current UI scripts use Maestro. There is no Maestro/ad-hoc-tap API yet; do
   not claim those tests passed or silently replace them with a native demo.

### Flutter acceptance

Use a real Flutter app with pubspec.yaml, committed pubspec.lock and ios/ project.
Select flutter-ios preparation, scheme Runner (or actual shared scheme), Debug and
forTesting false. Flutter iOS simulator release mode is deliberately rejected.
The recipe copies the approved SDK into .worker/flutter, enforces the pub lockfile,
and runs Flutter iOS configuration (including its Pods/SwiftPM processing). Do not
make the base SDK writable. Retry SDK preparation using a fresh revision.

Verify plugins/codegen, pub cache, SDK version/analytics settings, iOS configuration,
actual compilation/launch and screenshots. A bare Runner.app is the Flutter app,
not an XCTest runner; artifact selection accounts for that. Flavors/custom Dart
public defines are not yet exposed—report needed extension instead of inventing
arbitrary environment/shell parameters.

## Shared acceptance and reporting

- Test authentication, second-lease refusal, invalid recipe/environment rejection,
  no personal simulator access and operator-only resource approval.
- Confirm missing/untrusted controller and physical-Mac worker entry fail closed.
- Intentionally break a compile: retain meaningful logs and exit codes remotely.
- Verify screenshots cross the boundary as bounded artifact bytes, never host paths
  or links. Broker exports stay private. Check data directory ownership/ACLs.
- Check low-memory behavior, owner pause, job/VM timeout, lease expiry, reboot and
  host-network changes. Current process limits are not aggregate VM guarantees.
- Release/clean up the guest without touching the owner desktop or phone.
- Signing, device builds and USB deployment are NOT implemented. Read
  SIGNING_AND_DEVICES.md before adding them; no personal keychain in a guest and
  no main-account project builds as a 'safe' workaround.

Return tested commit/controller/image/toolchain versions, negative security test
results, actual job/revision IDs, outcomes for all three frameworks, screenshots,
resource observations, remaining limitations and any fixes pushed to Git. Distinguish
mocked Linux tests from Mac evidence. Never include credential values.
