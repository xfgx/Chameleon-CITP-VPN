# Windows 4.2.0 beta: IPC and desktop interface

## Defect found
The old server called ImpersonateNamedPipeClient before its first pipe read.
Microsoft documents the impersonation context as the last message read.
The broker now reads a strict size-bounded frame, then obtains the Windows SID,
then handles the request. No connection/status/action precedes SID validation.
The UI still verifies pipe server PID, SCM running state and installed executable.
No identity protection was disabled. Service RUNNING waits for pipe creation.
Transient pipe busy/missing states have bounded retry; errors preserve safe stages.

Reference: [ссылка удалена]

## Interface
Native Go/Win32: no Electron, WebView or additional analytics SDK. Sidebar has
Connection, My access and Diagnostics; owner-drawn named native buttons retain
keyboard navigation/focus indicators. Access field is masked, DPAPI storage unchanged.
Main states, counters and errors reflect the broker, not sample production values.
Separate status polling does not disable key typing. DPI scales native fonts/controls;
small-height windows have a vertical scrollbar. Closing the GUI does not disconnect.

UI patterns reviewed against the open Mullvad desktop repository; no GPL code,
assets, logos or trademarks were copied. The implementation/layout are original.
Reference: [ссылка удалена]

## Verification
Shared internal/desktopui geometry drives both native rendering and SVG previews.
Preview images are layout renders, NOT screenshots from an actual Windows run.
Go layout tests check bounds, duplicate controls, overlap and honest disconnected
states. Source regression tests enforce read→SID→action and identity protection.
Windows vet/build compile all IPC/GUI code. tools/IPC-SELFTEST.exe is a Windows
integration test using a separate random pipe and current-user SID; it has NOT
been executed on native Windows in this environment. Full native install,
activation/tunnel/reconnect/leak/DPI/accessibility checks remain required.
No claim that the screenshot's precise Windows error code was reproduced.

## Release / rollback
Private backup: <backup-dir>/windows-ui-4.2.0
Work branch: fix/windows-ipc-ui-4.2.0. Windows only is rebuilt; Android, bot and
RU VPN core/services are unchanged. Keep current bot readiness when reverting
Windows/source download selections. Do not restore the full old manifest blindly.
