Chameleon VPN 4.5.0 beta — Windows x64

Native C# WPF / .NET 10 self-contained UI; Go LocalSystem broker.
No .NET download is required on the user's machine. Windows 10/11 x64.
Install over 4.3.0/4.4.x after closing the old app. Since 4.5.0 the «Обновления»
tab checks the official site and installs newer versions itself (size, SHA-256
and version are verified; VPN is disconnected first; the app reopens after update). Since 4.4.1 the app always
runs as administrator (UAC prompt on launch) and, after one consent, starts the
BFE/Windows Firewall/ChameleonBroker services it needs. Closing the window hides
it to the tray; use tray menu "Выход" to quit. Protocol AUTO tries KS, then CITP.
Elevate with the SAME Windows account: the activation vault is per Windows user.

The old activation.dpapi format and device keys are retained for the same Windows
user. Do not copy app executables out of Program Files or reset the user vault.
UI: app\Chameleon.exe. Service: ChameleonBroker.exe. Legal notices: licenses\.
Bot activation: [ссылка удалена] . Bot integration documentation is retained
in the release source; no bot or Android deployment changed in this release.

KS uses 8-second epochs. Ensure Windows time synchronization is working.
Before capture routes, a fixed encrypted root-DNS diagnostic and ICMP probe are
sent; connection is never reported successful without an authenticated reply.
Reports show only synthetic probe counts, stage and controlled Windows errors;
no activation keys, payloads or user domains are included.

Firewall uses the Windows Firewall COM API, checks BFE/MpsSvc and active profile
state, verifies only our named rules and fails closed if privacy guards fail.
Do not disable Windows Firewall to work around a failure.
Read-only check: powershell -NoProfile -File tools\CHECK-INSTALL.ps1
Native acceptance checklist: DPI 100/125/150/200%, keyboard navigation, standard
user IPC, CITP and KS actual handshake, DNS leak, IPv6 leak, reconnect and uninstall.
Linux cross-build and source tests do NOT replace native Windows acceptance.
Installer is currently not Authenticode-signed. No claim of Windows acceptance.

Rollback: preserved 4.3.0 artifacts and backed-up download manifest on build-host.
To downgrade locally, uninstall 4.4.x first, retain LocalAppData\ChameleonVPN,
then install 4.3.0. Never reset the vault as a routine upgrade/downgrade step.
