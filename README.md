# mac-build-pool

Experimental macOS build/test API for remote agents. Project recipes cover **Swift,
Expo/React Native and Flutter iOS apps**. The host broker no longer executes
projects as the personal login account.

> **Owner update, 2026-11-12:** On-demand disposable macOS VM setup is now
> authorized. The Tart controller is implemented and undergoing private Mac
> acceptance. The earlier separate-user implementation remains an explicit,
> weaker opt-in, with no automatic fallback. Signing and USB remain disabled.
>
> Public isolated execution stays gated until a protected acceptance report
> matches the installed code/configuration and records real app, security and
> lease-expiry results. Unit tests and a controller file alone are insufficient.
> See [Tart setup and lease lifecycle](docs/TART_SETUP.md).

## Why the boundary changed

A separate Unix user and a list of API commands do not meet the requirement
“the cloud agent cannot access my documents, Mac environment or local network.”
Build scripts, Swift macros/plugins, npm lifecycle scripts, Podfiles, Dart build
hooks and tests all execute code. Existing host services can also execute outside
an inherited process sandbox. Framework-specific recipes are not security controls.

The architecture required for full isolation is:

```
Remote agent → authenticated host broker → isolated VM/network controller
                                                 ↓
                              disposable macOS guest: dependencies + Xcode
                                                      + iOS Simulator
                                                 ↓
                                   bounded logs / artifact bytes
```

- Broker stays `iosbroker`, never root or the personal login.
- Tart uses root-owned `/Library/ios-worker/vm.json` and a private protected
  Unix control socket, never a caller-selected executable or shell argv.
- The external `IsolatedRunner` contract remains available separately. See
  [docs/ISOLATION_CONTRACT.md](docs/ISOLATION_CONTRACT.md).
- A missing/untrusted controller cannot fall back to the previous `SudoRunner`.
- Default host installer removes this project's old native sudo grant/helper. It does
  **not** install a replacement VM controller or silently make the worker ready.
- Executor-side entry point refuses a physical Mac and shared/network mounts.
  This accidental-host guard is **not** an egress or complete isolation verifier.
- Network restrictions must be enforced outside untrusted guest processes and
  cover host, LAN, tailnet, VPN, IPv4, IPv6 and DNS/rebinding paths. NAT alone is
  insufficient. No personal mounts, clipboard, SSH-agent forwarding or keychain.

Do not install an adapter that simply invokes the old host worker or reports
`{"isolated":true}`. Implement and validate the controller contract first.

## Implemented recipes

| Recipe | Input | Preparation | Simulator build |
| --- | --- | --- | --- |
| `swift-ios` | App `.xcodeproj`/`.xcworkspace` | Resolve pinned Swift packages using Xcode; no Node/Ruby needed | Debug or Release; optional XCTest |
| `expo-ios` | App-root package.json + exactly one npm/Bun lockfile | frozen npm/Bun install → Expo prebuild → CocoaPods | Release + build-only embeds JS; Debug needs bundling/Metro planning |
| `flutter-ios` | pubspec.yaml + pubspec.lock + existing ios/ | Private copy of approved Flutter SDK → locked pub get → Flutter iOS config/Pods or SwiftPM | **Debug**, build-only; no Metro |

A plain Swift app may build directly without preparation. SwiftPM package-only
libraries without an app Xcode project are not yet a simulator-app workflow. The
Expo recipe regenerates ios/ with `--clean`; do not use it on hand-maintained iOS
projects. Flutter requires a checked-in ios/ project and does not replace your
app with a generated demo. Flutter SDK copies require a fresh revision on retry.
Yarn/pnpm, Flutter flavors/defines and private dependency credentials are not
implemented by these recipes yet. XCTest targets must actually exist; Expo and
Flutter preparation do not synthesize UI tests or run Maestro.

Owner-approved **guest** toolchains are selected by root-owned worker.json, never
by API input. Dependency installation defaults to disabled. Node/npm/Ruby/pod and
Flutter versions are provisioned into the guest base image by its owner, not
installed as root by a job. Flutter needs a writable SDK cache; the recipe copies
the read-only approved SDK into the disposable workspace rather than making the
base toolchain writable.

Each preparation uses `.worker/` for HOME, caches and temporary files. Xcode uses
the guest iosagent HOME so it can find that guest's CoreSimulator devices. These
environment settings are convenience, **not isolation**. Only `EXPO_PUBLIC_*`
variables may be supplied; they are public app configuration, not secrets.

## API and CLI

Normal API routes require the agent token. Resource overrides require a distinct
operator token which remains on the owner side. Exclusive leases cover a complete
build/launch/test session. See [the handoff](docs/LOCAL_AGENT_HANDOFF.md) for setup
and validation rather than installing this as though it were a ready sandbox.

| Route | Purpose |
| --- | --- |
| `GET /v1/health` | API health, queue/pressure, `executionMode` and `executorInstalled` |
| `POST /v1/leases` | Acquire exclusive VM session; optional simulator startup |
| `POST /v1/leases/{id}/renew` | Renew before expiry; two-hour absolute maximum |
| `POST /v1/sources` | Upload tar/gzip; returns ingest job + `revisionId` |
| `POST /v1/preparations` | Select `recipe`, revision, lease, optional scheme/publicEnv |
| `POST /v1/builds` | Build; configuration Debug/Release, forTesting boolean |
| `POST /v1/sessions` | Install/launch selected configuration; returns sessionId |
| `POST /v1/tests` | Run previously built XCTest products |
| `POST /v1/sessions/{id}/screenshot` | Capture artifact |
| `POST /v1/sessions/{id}/logs` | Collect simulator logs |
| `GET /v1/jobs/{id}` and `/logs` | Status and diagnostic tail |
| `GET /v1/artifacts/{id}` | Download broker-exported artifact |
| `POST /v1/jobs/{id}/approve` | Operator-only override |
| `POST /v1/leases/{id}/release` | Release session / fail pending jobs |

`executorInstalled` checks protected-file presence, **not** readiness, network
policy correctness, or a security attestation. Controller lifecycle/resource
integration must be completed before serving work (see contract).

After the controller has been implemented and verified:

```sh
export IOS_WORKER_URL='http://YOUR-MAC-TAILSCALE-IP:8741'
export IOS_WORKER_TOKEN_FILE="$HOME/.config/mac-build-pool/token"
# Token file mode 600; never put its value in argv or Git.
python3 cli.py health
python3 cli.py lease
python3 cli.py source source.tar.gz
python3 cli.py prepare --revision REV --lease LEASE --recipe expo-ios \
  --public-env-file public-env.json
python3 cli.py build --revision REV --lease LEASE --scheme CoupleJoy \
  --configuration Release --build-only --no-boot
python3 cli.py launch --revision REV --lease LEASE --configuration Release
python3 cli.py screenshot SESSION --output screenshot.png
python3 cli.py release LEASE
```

For Flutter use `--recipe flutter-ios`, scheme `Runner`, `--configuration Debug`
and `--build-only`. For a simple Swift app use its real scheme, optionally prepare
with `--recipe swift-ios --scheme MyApp`, then build Debug/Release. Use default
build-for-testing only when genuine XCTest targets exist.

Copy IDs from JSON responses. CLI waits are bounded and return at operator approval;
they do not approve jobs. `status JOB`, `logs JOB` and `wait JOB` resume inspection.
Do not release/replace a running session to bypass resource limits. Screenshots
must be downloaded to a new output path. Credentials are not forwarded on HTTP
redirects or through environment proxy settings.

Snapshot limits: 64 MiB uploaded and uncompressed. Exclude .env, credentials,
node_modules, `.worker`, .git, build outputs and caches. Dependencies are installed
inside the guest, not uploaded from Linux. The old native 20 GiB disk monitor and
per-process jetsam request are **not** substitutes for VM-level limits. They also
may need adjustment for cold Flutter/React Native caches after owner review.

## Signing and physical devices

Current build operations deliberately disable Apple developer signing and target
simulators. There is **no signing or USB-device service yet**. Simulator builds do
not need your Apple Development certificate or personal Apple ID.

Physical phones need device builds, development signing/provisioning and pairing.
Those belong to a separate, approved signer/deployer, not the build VM. See
[docs/SIGNING_AND_DEVICES.md](docs/SIGNING_AND_DEVICES.md). Do not import your personal
keychain into a guest or build arbitrary agent-produced Xcode projects under your
main account to bypass this separation.

## Tests and current limitations

```sh
python3 -m unittest discover -s tests -v
```

Linux tests use fake tools and cover recipes, SDK copying, policy, API, scheduling,
logs, artifact handling and no-fallback guards. No Swift/Flutter/Expo build is
claimed to have passed until actual Mac evidence is recorded. Native VM launch, network
confinement, signing, phone deployment and reboot recovery require Mac validation.

The Tart implementation covers expiring leases, VM cleanup and an external
network boundary. Real Mac acceptance is still in progress; consult the recorded
evidence before enabling it. Reboot/FileVault recovery, host network changes and
framework-specific edge cases need explicit verification. Do not weaken the
isolation contract to obtain a passing screenshot.
