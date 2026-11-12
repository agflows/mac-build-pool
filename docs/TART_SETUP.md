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

Only the small broker/controller remains while idle. The guest has a configured
4, 6 or 8 GiB RAM ceiling; it does not resize itself to each compiler's measured
needs. Its macOS overhead exists while the lease is active. Stopping it releases
its RAM; a powered-off image uses disk only. The default installed profile uses
4 GiB and four virtual CPUs, serial builds and a 100 GB sparse guest disk.
Warning pressure requires owner resource approval before starting the guest;
urgent pressure stops this guest without touching personal apps or simulators.

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
