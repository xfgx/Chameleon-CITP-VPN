# Android client 4.5.0

- Disconnect is immediate: `ChamVpnService.stopVpn()` follows the RU-node client and releases the
  core and TUN without waiting for the worker (CITP re-dial up to 10 s, 3 s maintenance sleep,
  15 s first-KS-reply wait). A stale worker cleans up only the core start it owns
  (`coreOwner`), and a new session joins the previous worker before touching the shared core.
- Native core (`mobilecore.aar`) is unchanged; its stop path is identical to the RU-node source.
- New **Обновления** tab: opening it fetches `/vpn/manifest.json`; if the Android release is newer,
  «Обновить» downloads `/vpn/download/android` into the private cache, verifies size, SHA-256,
  package name, versionCode/versionName and signer certificate, then hands it to
  `PackageInstaller` (Android asks the user to confirm; unknown-sources permission is requested
  once). A quiet check also runs at launch and marks the tab with •.
- Clients on 4.3.0 must install 4.5.0 manually once; later updates go through the app.
