# Required isolated-executor contract

> **Owner update, 2026-11-12:** The owner now authorizes on-demand Tart VM
> setup and real build/simulator validation. The earlier code-only restriction
> is superseded. Keep developer signing and USB disabled. The controller candidate
> is undergoing private acceptance; see [Tart setup](TART_SETUP.md). All isolation
> requirements below remain in force; there is no native-host fallback.

This is the acceptance specification for the Mac-side controller, not a claim
that the new Tart candidate has completed real security validation. The shipped host broker intentionally fails jobs when
`/Library/ios-worker/isolation-executor` is absent. Do not replace this requirement
with a flag, an echo script, an SSH shell on the host, or the legacy native runner.

## Threat model

The remote agent is controlled by the owner but can make mistakes, encounter
prompt injection, or build compromised dependencies. Treat **all project code,
package scripts, tests, native plugins and guest outputs as untrusted**. Protect
personal files, host services, keychains, host/LAN/VPN/tailnet connectivity and
signing/device credentials. Possession of the agent token is not operator approval.
The owner-installed broker/controller and hypervisor are trusted components.

## Host controller interface

`IsolatedRunner` invokes only the root-owned, non-writable executor path above,
without sudo or shell interpolation, as iosbroker. It sends one JSON object on
stdin; no tokens, operator credentials, SSH agents or caller environment. Stdout
must be one bounded JSON result with `ok: true`. Failures exit nonzero and may
return the existing structured stderr (`message`, `error`, `exitCode`). Logs are
untrusted text, never commands.

Fields include `op`, `job_id`, `lease_id`, `revision_id`, `session_id`, approved
logical device ID, scheme, recipe, configuration, for_testing, public_env, artifact
ID, source archive reference and the broker's operator-approved resource flag.
No field grants arbitrary host command/path access. Revalidate identifiers in the
controller and translate only controller-owned staging paths.

Operations mirror the executor-side worker: ingest, prepare, build, launch,
uitest, screenshot, logs, reset, boot, booted and shutdown. **All project execution
and CoreSimulator use occur inside the guest.** `booted` is a side-effect-free
query; it must not create/start a VM. No active guest means false, never inspect a
personal host simulator as fallback.

`worker_exec.py`, its protected modules and worker config form a possible guest
payload. The entry point requires a supported VirtualMac model and rejects shared
filesystem mounts. This only helps catch accidental host deployment. It does not
prove that an arbitrary VM's network or host integration is restricted.

## VM and filesystem boundary

- Fresh approved macOS image/clone per lease; do not import personal user sessions.
- Agent code is non-admin in the guest. Xcode, toolchains and worker modules are
  owner-managed. Keep its guest sudo surface narrowly scoped if one is necessary.
- No host home/workspace mounts, shared clipboard, dragged files, shared keychain,
  SSH-agent forwarding, USB passthrough, camera/microphone or broad desktop control.
- Prefer byte/stream transfer, not a writable host shared directory. Source
  extraction must happen inside the guest. Host ingestion can store an opaque
  bounded blob pending guest ingestion; never extract arbitrary source onto host.
- Guest archives/paths/metadata are not trustworthy. Export only explicitly
  permitted artifact bytes with size/type limits and safe controller-chosen names.
  Never accept a guest `artifact_path` as permission to read a host path.
- Pin base image/toolchain versions. Isolate dependency caches by project/trust
  domain; a compromised job must not poison the next lease's base image.
- Dispose of guest data after the session/retention window; bound host staging,
  exports, log storage and VM image space.

Tart/Lume or another macOS VM backend can implement this. Review its license and
security/host-integration behavior before distributing it. A virtualization tool's
normal developer-friendly defaults are not a ready security profile.

## Network boundary (mandatory, not NAT alone)

Enforce policy outside untrusted job processes; preferably at the VM network
boundary. Do not trust npm proxy variables, the guest's shell config, or an agent-
editable firewall. Guest code must not be able to disable or route around policy.

Required coverage:

- Deny new connections to host addresses/gateway services, physical LAN, tailnet,
  corporate VPN routes, peer VMs, loopback-on-host, link-local/metadata endpoints,
  multicast/broadcast and all relevant IPv4 **and IPv6** ranges.
- Account for networks using public address space, the host's public IPv6/WAN
  addresses, network changes and proxy/DNS behavior. Fail closed while updating.
- Package downloads only through an owner-controlled egress policy, ideally a
  narrowly exposed HTTP(S)/SOCKS proxy with explicit destination rules. Check
  resolved destinations and redirects against policy, not just hostname strings.
  Block DNS rebinding, direct-IP, alternate-port, IPv6 and non-proxy bypasses.
- Explicitly approved public app backends may be required for runtime testing.
  Approval to fetch dependencies is not arbitrary internet or network access.
- The minimal control channel is separately authenticated, scoped, and not a
  general-purpose host network tunnel. No whole-tailnet membership for guest jobs.
- Keep guest-internal loopback available where needed for Xcode/Simulator. This
  must not be confused with access to the physical host's loopback services.

Example pitfall: a VM tool advertising public-only networking may still allow its
host gateway. Do not assume this is safe. Probe host services and every escape
route. The Tart candidate enforces disconnected Ethernet plus a host-validated HTTPS
relay; complete these real tests before public activation.

## Lifecycle integration still to implement

The current scheduler's job serialization and lease bookkeeping are not a full
VM controller. Complete and test these integrations before installing an adapter:

1. Associate each lease/revision with exactly one owned guest. Source ingest has
   no lease field currently; stage it without execution, then attach/ingest inside
   the explicitly leased guest when requested. Do not guess across active leases.
2. Add explicit controller notification for lease acquisition/release, failure,
   timeout, crash/reboot and expiry; rehydrate or terminate stale sessions safely.
   Current release fails pending API jobs but is not a guest-destruction hook.
3. Start a VM only after resource admission. VM RAM is heavier than a native
   compile: warning pressure must not implicitly permit a new 8 GB VM merely
   because the old native build admission allowed compilation at warning.
4. Enforce VM-level CPU/RAM/disk and bounded concurrency; pause/stop on owner request.
   The old process-level limits are not VM or aggregate limits. Existing timeout
   process killing must not leave the guest running or kill unrelated host work.
5. Map device IDs only to the leased guest's simulator. No personal device access.
6. The controller must clean up its guest on completion/cancellation/lease expiry.
   Keep interactive sessions alive only within explicit owner policy.
7. Add capability/version negotiation so clients cannot mistake controller-file
   presence for a ready, security-verified worker.

On a 16 GB M1, an 8 GB guest is a practical *experiment*, not a guaranteed comfortable
always-on service. Prefer owner-approved/idle-only operation. Do not disable memory
approval or kill the owner's simulator just to get a test to pass.

## Required negative tests on the real Mac

Use harmless canaries and owner-approved test services, never real secrets. Run
checks from npm lifecycle scripts, Swift build phases/macros, Flutter/Dart hooks,
XCTest processes, simulator apps and spawned/daemonized children—not only from
an interactive guest shell.

- Cannot read a canary in personal Documents, SSH/keychain locations, broker home,
  or unrelated host/workspace paths. No host shared mount or agent forwarding.
- Cannot contact canary services on host LAN/loopback/tailnet/VPN/gateway or another
  guest via IPv4, IPv6, hostnames, DNS rebinding, redirects or direct sockets.
- Approved dependency fetch works; disallowed destination fails, including children.
- Cannot modify broker/controller/base toolchain, acquire another job's lease,
  export a symlink to host files, or self-approve resource/sign/install requests.
- No stale VM/process after timeout, crash, owner pause or lease expiry.
- Do these again after reboot/FileVault unlock and a host network change.

Record actual results and tested controller/OS/image versions. Do not weaken the
contract to pass a framework smoke test. Signing and USB require the separate
boundary in SIGNING_AND_DEVICES.md and are not implied by passing simulator tests.
