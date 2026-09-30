#!/usr/bin/env bash
set -euo pipefail
node="$(cat /etc/chameleon/build-node 2>/dev/null || true)"
[[ "$node" == build-host || "$node" == ru ]] || { echo "Approved build node required" >&2; exit 1; }
[[ "$(id -u)" != 0 ]] || { echo "Build as isolated non-root account" >&2; exit 1; }
cd "$(dirname "$0")/.."
out="${1:?absolute private output directory required}"
[[ "$out" == /* ]] || exit 1
mkdir -p "$out"
export PATH="/opt/chameleon-toolchain/go/bin:$PATH" GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS=-p=1
: "${GOPATH:?}" "${GOCACHE:?}"
[[ "$(go version)" == *go1.26.6* ]] || exit 1
checksum="$(sha256sum "$out/wintun.dll" | cut -d' ' -f1)"
[[ "$checksum" == e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce ]] || { echo "Wintun integrity mismatch" >&2; exit 1; }
python3 scripts/test-windows-packaging.py
python3 scripts/test-windows-ipc.py
python3 scripts/test-client-440.py
go test ./cmd/chamd ./internal/clientactivation ./internal/desktopui ./internal/chaossync ./internal/ksprobe
go vet ./cmd/chamd ./internal/clientactivation
resource=cmd/chamd/resource_windows_amd64.syso
trap 'rm -f "$resource"' EXIT
# Pinned build-only generator, outside the product module. Go verifies sums.
go run github.com/akavel/rsrc@v0.10.2 -arch amd64 -ico packaging/windows/assets/chameleon.ico -manifest packaging/windows/assets/chameleon.manifest -o "$resource"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./cmd/chamd ./cmd/vpn-service-setup ./internal/winipc
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath \
 -ldflags "-H=windowsgui -X main.productBuild=broker -X main.wintunSHA256=$checksum" -o "$out/ChameleonBroker.exe" ./cmd/chamd
python3 scripts/verify-windows-resources.py "$out/ChameleonBroker.exe"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -o "$out/broker-setup.exe" ./cmd/vpn-service-setup
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c -o "$out/IPC-SELFTEST.exe" ./internal/winipc
cp packaging/windows/assets/chameleon.ico "$out/"
cp packaging/windows/{WINDOWS-README.txt,CHECK-INSTALL.ps1} "$out/"
cp packaging/THIRD-PARTY-NOTICES.txt "$out/"
cp packaging/windows/CORRESPONDING-SOURCE.txt "$out/"
cp packaging/windows/licenses/Wintun-LICENSE.txt "$out/WINTUN-LICENSE.txt"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
(cd desktop/Chameleon.Windows && /opt/chameleon-toolchain/dotnet/dotnet publish -c Release -r win-x64 -p:RestoreLockedMode=true -o "$out/app")
cat "$HOME/.nuget/packages/microsoft.netcore.app.runtime.win-x64/10.0.12/LICENSE.TXT" "$HOME/.nuget/packages/microsoft.windowsdesktop.app.runtime.win-x64/10.0.12/LICENSE" > "$out/DOTNET-LICENSE.txt"
cp "$HOME/.nuget/packages/microsoft.netcore.app.runtime.win-x64/10.0.12/THIRD-PARTY-NOTICES.TXT" "$out/DOTNET-THIRD-PARTY-NOTICES.txt"
python3 scripts/verify-wpf-resources.py "$out/app/Chameleon.exe"
makensis -V3 "-DBUILD_DIR=$out" "-DOUTPUT=$out/Chameleon-4.5.0-windows-setup.exe" packaging/windows/chameleon.nsi
python3 - "$out" <<'RECEIPT'
import hashlib,json,pathlib,subprocess,sys
out=pathlib.Path(sys.argv[1]); names=['ChameleonBroker.exe','broker-setup.exe','IPC-SELFTEST.exe','chameleon.ico','wintun.dll','Chameleon-4.5.0-windows-setup.exe']
value={'version':1,'product_version':'4.5.0','build_node':'build-host','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'native_windows_acceptance':False,'authenticode_signed':False,'resource_generator':'github.com/akavel/rsrc@v0.10.2','frontend':'C# / WPF / .NET 10.0.401 self-contained','artifacts':{n:{'bytes':(out/n).stat().st_size,'sha256':hashlib.sha256((out/n).read_bytes()).hexdigest()} for n in names+[str(p.relative_to(out)) for p in sorted((out/'app').rglob('*')) if p.is_file()]}}
(out/'WINDOWS-BUILD-RECEIPT.json').write_text(json.dumps(value,indent=2)+'\n')
RECEIPT
