# Windows 4.4.0 beta

## Changes
- Native C# / WPF .NET 10 UI, Segoe UI, vector Paths, layout rounding,
  PerMonitorV2, keyboard focus and scrollable pages. No bitmap-scaled GDI UI
  shipped as the client. Background status polling does not toggle progress or
  disable/recreate controls.
- Standard-user frontend under `app/`, protected Go broker under Program Files.
  Named-pipe server PID must match running SCM service and exact protected broker
  path BEFORE any credential transmission. Interactive users only have limited
  broker-process query rights, never elevated service control.
- Backward-compatible CurrentUser DPAPI vault: activation and device identity
  retained. Invalid vaults are not silently reset. Explicit CITP/KS selection.
- Windows Firewall COM API replaces netsh creation. BFE/MpsSvc, enabled active
  profiles and modifiable policy checked; fixed own rules verified. Remote DNS
  CIDRs exclude all 127/8. Failure aborts connection and removes only own guards.
- KS handshake no longer depends exclusively on hub ICMP: fixed root-NS query
  to 8.8.8.8 travels INSIDE the authenticated KS tunnel before capture routes.
  Valid AEAD response with correct destination required; no claim of connectivity
  merely from a UDP send. Probe reply is consumed, not injected as user traffic.
- CA-validated fixed HTTPS clock sanity check; >12s offset yields `vpn.ks.clock`.
  Does not set system clock or expand the KS replay/epoch acceptance window.
- `vpn.ks.udp_send`, `vpn.ks.udp_read`, `vpn.ks.auth` and safe probe counts;
  firewall substage/HRESULT. No credential, payload or browsing-history report.
- Runtime dependencies self-contained; pinned SDK10.0.401/runtime10.0.12.
  Core and WindowsDesktop licenses under `licenses/`; Wintun unchanged.

## Limitations / acceptance still required
Linux cross-build, Go tests/vet, compiled PE icon/manifest checks, source guardrails
and inspected HTML layout approximations PASSED. HTML previews are not WPF
screenshots. No Windows desktop/SCM/Wintun device was available for native testing.
No proof yet that either reported failure is resolved on the user's actual PC.
A blocked UDP path, mismatched node provisioning, GPO, stopped Firewall services,
or third-party security software can still prevent connectivity.
Installer is NOT Authenticode-signed.
Read-only RU audit via ops-host was blocked by missing SSH dependencies and <6MB disk.
No RU configuration, bot, issuer database or Android artifact was changed.

## Native acceptance
Install over closed 4.3 client, same standard Windows account. Retain vault.
Test non-admin IPC, activate existing key, both transports, actual public IP,
DNS/IPv6 leak resistance, reconnect, DPI100/125/150/200%, move between displays,
resize, keyboard focus, copy diagnostics and uninstall. Do not disable Firewall
as a workaround. Report stage/HRESULT and synthetic probe counts on failure.

## Build on approved node
As chameleon-build, with verified Wintun in private output directory:
`bash scripts/build-windows-product.sh <build-dir>/windows-4.4.0`
The script checks build-node marker and refuses root execution.

## Release / rollback
Immutable Windows4.4 and corresponding source assets; Android remains4.3.0.
Download manifest publication must preserve bot/issuer/Android metadata.
Backup: `<backup-dir>/windows-4.4.0/` on build-host.
Server rollback script only restores Windows/source entries from backup, verifies
old artifact hashes, preserves unrelated current fields; it changes no service
or database. Older installers remain in releases.
Local downgrade: uninstall4.4 first, retain LocalAppData/ChameleonVPN, then install
4.3.0. Old4.3 service helper refuses the new broker path, so do not overlay the old
installer directly over an installed4.4 service.
