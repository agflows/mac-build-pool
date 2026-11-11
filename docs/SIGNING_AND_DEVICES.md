# Signing and USB deployment: design, not implemented

> **Owner update, 2026-11-11:** The owner subsequently accepted separate-user
> execution and requested **code preparation only; keep the service unchanged**.
> See [Native user mode](NATIVE_USER_MODE.md) for that explicit opt-in path.
> The VM requirements below continue to apply to `isolated-only`, not to the
> weaker native mode. Signing and USB APIs remain disabled in both modes.

## What signing means

There are different artifacts/workflows:

- **iOS Simulator:** no Apple Development certificate, provisioning profile or
  personal Apple ID is needed. Xcode may use simulator/ad-hoc signing internally;
  that is not a reason to expose a developer keychain. Current worker commands
  disable developer signing and target the simulator.
- **Physical iPhone:** compile a device-targeted app (a simulator .app is not the
  same binary), sign it with an appropriate development identity, and provision
  the allowed device/capabilities. Developer Mode/trust/pairing also need setup.
  A free Personal Team can suffice for many personal-device experiments; paid
  membership is needed for distribution and some capabilities/workflows.
- **TestFlight/App Store/ad-hoc distribution:** additional signing, provisioning,
  account roles and distribution policies apply. Not part of the current worker.

Installing an app does not flash or replace the iPhone's operating system.

## Recommended staged workflow

1. Build/test/screenshots entirely inside the isolated simulator guest. No
   signing key, personal Apple ID or USB pairing credentials in that guest.
2. Add device builds that produce an unsigned device artifact. Export it as
   untrusted bounded data, not executable code on the host.
3. A distinct trusted signer/deployer presents a local approval request containing
   artifact digest, source revision, bundle ID, target phone, signing identity,
   requested entitlements and expiry. The approval UI can be on the main desktop;
   the source/build process must not run as that desktop user.
4. After explicit owner approval, sign using a dedicated development keychain and
   allowlisted provisioning/entitlements, then install only onto the approved
   paired test phone. The installed bytes must match the approved digest/signing
   transformation. Mutating an artifact invalidates approval.
5. Return a bounded deployment result. The cloud agent does not get private keys,
   raw pairing records, unrestricted devicectl commands, phone backup access,
   unrelated app data or a main-account shell.

Broker/operator roles for resource approval and signing/install approval should
remain distinct. Approving a build must not approve deployment to a phone. USB
attachment must not automatically authorize remote use. First-use trust prompts
and Developer Mode can require interaction/unlocking on the phone itself; a Mac
notification cannot bypass those Apple requirements.

A signer is security-sensitive. It must safely handle hostile bundles, nested
frameworks, links, entitlements and profiles without executing build scripts or
using an unrestricted 'codesign this host path' API. Keep distribution identities
out of the early development signer. Prefer a dedicated test phone with no personal
data; a signed app is still untrusted software and can exercise granted permissions.

## Manual handoff versus automatic deployment

The simplest initial handoff is a **device artifact** plus a controlled local
sign/install step. A suitably signed .app/.ipa can be installed through appropriate
Xcode device tooling without rebuilding the source under the personal account.
Precisely supported Xcode/import/signing steps must be tested for the installed
version. An unsigned artifact is not automatically installable by drag-and-drop.

Opening the source project in the main account is useful for human review/debugging,
but pressing Build can execute agent-controlled scripts, package plugins and Swift
macros with personal-account privileges. This **does not preserve the isolation
model**. If a human deliberately chooses it, make the trust change explicit; never
automatically open/build arbitrary projects as a supposedly safe escape hatch.

The recommended product path is simulator first, then a local, narrowly scoped
sign/install helper with an approval UI. Neither the signer nor USB bridge nor a
main-desktop approval UI is implemented in this change. All existing API builds
remain simulator-only and unsigned; no personal keychain permission is requested.
