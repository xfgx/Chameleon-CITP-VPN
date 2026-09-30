# Chameleon VPN 4.5.0 beta — Windows x64

- New «Обновления» tab (same function as Android 4.5.x): checks `/vpn/manifest.json` at start and on demand,
  shows the available version, downloads `/vpn/download/windows` into `Program Files\Chameleon VPN\updates`
  (admin-only), verifies size, SHA-256, file name and PE FileVersion against the manifest, refuses downgrades,
  disconnects VPN, then runs the installer silently (`/S /UPDATE`).
- Installer: in `/UPDATE` mode waits for the UI to exit, performs the normal broker stop/replace/start and reopens
  the app with `-updated`. Manual installs are unchanged. Uninstall removes the `updates` folder.
- Broker, VPN core, KS/CITP, firewall and activation vault are unchanged from 4.4.1.
- Not Authenticode-signed; trust root is the HTTPS site + manifest SHA-256. Native Windows acceptance pending.
