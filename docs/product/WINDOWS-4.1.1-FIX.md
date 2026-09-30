# Windows installer 4.1.1 beta

The previous NSIS installer nested unescaped quotes in sc.exe binPath and invoked
sc.exe from a 32-bit process without controlling WOW64 redirection. The screenshot
contains only a generic failure, not its Windows error code, so the precise native
error is not established. Service registration now uses an x64 helper and the
Windows SCM API, with separately escaped path/argument, ownership checks, bounded
stop/start waits and Windows error text. No VPN connection is started at install.

Notices are installed under licenses (including MIT and Wintun). Documentation
and diagnostic tools are separate. Personal DPAPI activation stays in LocalAppData,
never in a shared licenses folder. App, installer and uninstaller use a multi-size
Chameleon icon. App default is the standard-user native GUI in product builds only.

Build on build-host as chameleon-build: scripts/build-windows-product.sh OUTPUT_DIRECTORY
with isolated GOPATH/GOCACHE and the verified Wintun DLL in OUTPUT_DIRECTORY.
Build-only resource generator: github.com/akavel/rsrc v0.10.2.

Required native acceptance: clean install (Program Files path with spaces), retry
after the old failed installer, update, ordinary-user GUI/activation/connect,
stop/start and uninstall. tools/CHECK-INSTALL.ps1 is read-only. This Linux build
is not native acceptance and does not provide Authenticode signing.

Rollback: server backup <backup-dir>/windows-fix-20260930 contains the
previous manifest, release receipt, setup executable and source-files snapshot.
Restore only manifest/source-download selection to withdraw the new Windows beta;
do not touch RU or VPN core services. Client downgrade to 4.1.0 is not recommended
because it restores the known installer defects. Preserve user DPAPI activation.
