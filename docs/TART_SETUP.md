# On-demand Tart controller

The controller implementation is undergoing private Mac acceptance. A source
checkout, passing unit tests, or a running controller alone does not enable the
public build API. Activation requires evidence for a real app build, negative
security checks and lease expiry against the installed code/configuration.

## Runtime and lease

The installed host broker runs as `iosbroker`; the private controller runs as the
non-admin `iosvm` account. Guest projects run as a different non-admin `iosagent`
inside macOS. There is no native fallback. Developer signing and USB stay off.

Acquiring a lease reserves one guest and queues its startup after resource
admission. `bootSimulator: true` also starts the guest's mapped simulator and
returns a session ID for screenshots and logs without a project build. A lease
lasts at most 300 seconds per renewal, with a two-hour absolute limit. Renew while
working or interacting with the simulator; job completion alone does not end a
lease. Release or expiry stops and deletes its disposable APFS clone. An expired
lease cannot be revived. Daemon restart reaps only its own `lease-*` guests.

Only the small broker/controller remains while idle. The guest sees a fixed
4, 6 or 8 GiB RAM limit. Apple's Virtualization framework allocates physical
pages on demand, and Tart does not shrink the guest's RAM limit during a lease.
Host memory can reach the full guest limit plus virtualization overhead.
Stopping the guest releases that memory. The installer defaults to 4 GiB, four
virtual CPUs and a 100 GB sparse guest disk. Use `--memory-mib 8192` for the
8 GiB profile. The host and guest each manage swap on their startup disks.

The Tart broker runs one job at a time. Inside a build, Xcode can run up to
four build operations concurrently. The controller shuts down and verifies
all guest simulators before preparation or compilation. A build with
`bootSimulator` enabled queues a separate simulator boot after it succeeds.
The Tart worker automatically approves VM and simulator startup at warning
pressure, including during paging, without posting a notification.
Urgent or critical host pressure holds new work and stops the guest without
touching personal apps or simulators.
Builds have a 45-minute deadline, including Xcode scheme discovery. A timed-out
command returns its bounded diagnostic output before the controller reaps its guest.

## iOS simulator interaction

For iOS interaction, provision the checksum-pinned AXe archive with
`scripts/provision-tart.py --axe ARCHIVE`. The agent addresses the session
returned by `launch` or `lease --simulator`. Input waits for that session
to be ready and shares the build and simulator queue.

```sh
python3 cli.py input SESSION '{"action":"displays"}'
python3 cli.py input SESSION '{"action":"tap","x":120,"y":250,"hold":0.6}'
python3 cli.py input SESSION '{"action":"drag","x":120,"y":250,"endX":160,"endY":500}'
python3 cli.py input SESSION '{"action":"pinch","scale":1.5}'
python3 cli.py input SESSION '{"action":"button","button":"lock"}'
python3 cli.py screenshot SESSION --output lock-screen.png
```

Coordinates use logical points. Other actions include `swipe` (same
coordinates as drag), `rotate` (two-finger rotation with x, y, radius
and degrees), `describe` (accessibility tree), `type` (US-layout text),
and `key` (HID code). The button action accepts home, lock, side-button,
siri and apple-pay.

## Apple Watch simulators

Use Xcode's complete Apple watchOS 26.5 arm64 `.exportedBundle` with
`scripts/provision-tart.py --watch-runtime`. The bundle preserves Apple's
verification metadata. Xcode imports it inside the guest and the worker Apple
Watch is paired with the dedicated worker iPhone.
The host broker exposes the logical watch device in `GET /v1/health` when the
reviewed base contains the configured Watch.

Use the watch app's shared Xcode scheme and pass its logical ID through
`--device` on `lease --simulator`, `build`, `launch` or `test`. Preparation
uses the Swift recipe. Screenshots and logs use the resulting session ID.
The iPhone stays the default destination. Signing and physical-device access
remain disabled for both platforms.

## Owner menu

Run `scripts/make-menu-app.sh`, then open the app it prints. It has a single
menu bar icon with the worker state, current session name, disk and memory
usage, End Session, and Quit. Set a name with `cli.py lease --name`.
End Session releases the entire leased guest. Quit closes the menu app.
When a job is waiting for memory approval, the owner can approve that job
from the menu. The approval applies to the selected job in the current
lease. Urgent memory pressure still holds new work and stops the guest.

The local control socket accepts the configured owner's macOS UID and
exposes status, job approval, release, and Copy Agent Instructions. The copy action reads
the public agent token on demand and copies it with the Tailscale URL and
current remote readiness. It does not include the operator or validation
credentials. Total memory adds the menu app's macOS memory footprint to the
combined footprint of both dedicated service accounts. It includes the build
listener, VM controller, virtualization process and helpers under those accounts.
Disk is allocated storage for the installed worker and its data. Retired native
workspaces and macOS account caches are outside that measurement. APFS shared
blocks can be counted in more than one image while a lease is active.

## Boundary

Tart receives a disconnected Ethernet socket pair. The host drains every frame
and injects none. There is no NAT, guest DNS uplink, IPv6 uplink or host gateway
service. No host shares, clipboard, audio, USB, SSH agent or personal keychain
are attached. Tart's guest control channel carries bounded source/result bytes.
Source extraction and project execution happen only inside the guest.

A guest-local TLS proxy uses the control channel to reach a host-owned HTTPS
relay. The host resolves exact approved domains, rejects private/host/on-link/VPN
addresses and mixed DNS answers, connects to the checked numeric address and
verifies the real upstream TLS certificate. It then validates canonical HTTP
requests, including their Host and framing, before forwarding them. Arbitrary
CONNECT tunnels, absolute proxy URLs, request smuggling, domain fronting and
package uploads are rejected. Only package hosts and explicitly approved public
app backends are reachable. This policy cannot be disabled by project settings.

The relay's CA and private keys are generated inside the pristine guest. Only
its public CA is installed in that guest and its disposable iOS simulator. No
relay CA is added to the physical host. This TLS setup is separate from Apple
developer signing. The dedicated host `iosvm` keychain holds only Virtualization
identity data and receives no developer or personal keys.

## Provision and activate

`scripts/toolchain-pins.json` records the reviewed downloads. Provision from the
pinned macOS image, copying the owner's independent local Xcode installation and
simulator runtime as data. `scripts/provision-tart.py` performs trusted image
maintenance, creates the guest job account, replaces public image credentials,
installs the restricted relay/tools, creates a fresh simulator and shuts down
before promoting `worker-base`. Never promote a guest after running projects.

Keep image/runtime/provisioning outputs in an owner-private persistent directory,
not a shared temporary checkout. The reviewed root installer stages a separate
localhost validation broker with temporary credentials while public execution
is off. It preserves the existing public token files and removes the legacy
native helper/sudo grant. Do not stop an occupied broker or overwrite a live
controller. Root-owned code and image identity checks fail closed after changes.
When a reviewed, project-free image supersedes the installed base, use
`--replace-base` while the controller is idle and its lease guests are gone.

The owner can opt in to a single-peer remote trial by adding `--peer-trial`
after the validation configuration path in its launch arguments. The protected
`/Library/ios-worker/peer-trial.json` names one Tailscale IPv4 address in
the `peer` field. The trial uses the regular Tailscale address and agent
credential. Both trial listeners share one scheduler and the same isolated
guest. Operator approval stays on the loopback listener. The health response
identifies the peer listener with `remoteTrial`.

After real private acceptance, `--activate --report` checks the app/security/lease
results and compares the report's screenshot, installed code and VM
configuration digests against the actual files. Queued public jobs recheck
acceptance immediately before execution. Any subsequent runtime-code/config
change invalidates readiness until reviewed and validated again. The public
endpoint uses its existing Tailscale address and
agent credentials. Keep the owner-only operator token off remote clients.

Expo supports exactly one npm or Bun lockfile and frozen dependency installation.
Flutter uses a job-private copy of the immutable SDK and enforced pub lockfile.
Only public `EXPO_PUBLIC_*` configuration is accepted. This is not permission to
forward backend secrets, signing credentials or host environment variables.

## Acceptance evidence

Run the unit suite, then record actual Mac image/toolchain/source versions,
API job IDs and screenshot bytes. Use the real CoupleApp Release build with an
embedded bundle, the Swift fixture with its pinned package/XCTest target, and a
real Flutter Debug app. Run `scripts/guest-negative-probe.py` inside the guest
and from dependency/build hooks. Also validate API authentication/operator
separation, source/artifact escapes, timeout/restart/expiry cleanup and memory
admission. Report any untested reboot/network-change behavior explicitly.

Tart's personal-workstation use is royalty-free under its [published license
terms](https://tart.run/licensing/); review those terms before other deployment.
