# Client 4.3.0 beta

## Windows fixes
- LocalSystem broker merges an Interactive-user PROCESS_QUERY_LIMITED_INFORMATION ACE into its process DACL before the pipe is ready. This permits PID/path verification by the standard-user client. It does not grant memory read/write, process termination, token access, service control or elevation. Existing service/pipe ACLs, PID/path checks, strict frames and remote rejection remain.
- Internal -tun-probe dispatch precedes the product GUI. Previously the packaged GUI default intercepted it, causing a hidden GUI and a 30-second preflight timeout.
- Safe stage-specific connection codes replace the generic error. Only controlled descriptions, whitelisted activation classifications and numeric OS errors reach the report.
- Native painting uses an offscreen 2x bitmap and halftone downsample. Buttons fill their complete corner background. Layout does not move controls or recreate fonts on unchanged status polls.

## Protocol selection
Both clients have a separate Protocol page. Windows defaults to CITP. Android preserves its previous automatic CITP-then-KS behavior under a visible Auto option; manual CITP/KS selections are strict. Explicit selection is persistent and locked while connected/connecting/stopping. Profiles come only from the authenticated activation API. Missing KS profile is an explicit error, not a silent CITP fallback.

Android keeps the existing mobilecore AAR/data plane. Only native UI and profile selection are changed. Windows KS uses existing chaossync rotating AEAD (c2n/n2c, 8-second epoch) with Wintun. An authenticated node reply is required before capture routes. Keys are never written to files or passed in arguments. DNS for Windows KS is resolved as DNS-over-HTTPS to Google's dns.google (8.8.8.8) through captured KS routes; DNS contents are not logged. IPv6 and plaintext external DNS guards remain. Existing Android DNS behavior is unchanged.

## Update/acceptance
Close the Windows app, install over 4.2.0, then launch its shortcut as a NORMAL user. Keep existing DPAPI key. Check Diagnostics, CITP connect/disconnect and KS separately. Install Android 4.3.0 over 4.1.0 with the same signing certificate: the encrypted vault remains. Check both transports, QR links, rotation, 320dp width, 150%/200% font scale, keyboard and accessibility.

Closing Windows GUI does not disconnect the service. Use Disconnect first to change protocol. No production bot/RU/core service changes are part of this release.

## Verification limitations
Linux unit/source tests, Windows cross-compilation/PE-resource inspection, Android compilation/lint/signature checks and layout previews are not native device acceptance. Windows runtime and an Android emulator/device are unavailable on the build host. User-reported runtime issues remain subject to native acceptance.

## Rollback
Source backup: <backup-dir>/client-4.3.0. Source baseline: 4ec0cbc. Atomic download rollback preserves current bot fields and unrelated assets. Reinstall Windows 4.2.0 only after disconnecting and closing 4.3.0 (it retains the reported old bugs). Android's lower versionCode normally forbids downgrade; do not uninstall casually, because uninstall removes the local vault. Prefer a forward-fix build with a higher versionCode. Old release files are retained.
