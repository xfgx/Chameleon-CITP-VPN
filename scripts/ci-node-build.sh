#!/usr/bin/env bash
set -euo pipefail
node="$(cat /etc/chameleon/build-node 2>/dev/null || true)"
[[ "$node" == build-host || "$node" == ru ]] || { echo "Only build-host/RU may compile this project." >&2; exit 2; }
[[ "$(id -u)" != 0 ]] || { echo "CI must be non-root." >&2; exit 2; }
export PATH="/opt/chameleon-toolchain/go/bin:/opt/chameleon-toolchain/gradle-8.7/bin:$PATH"
export GOMAXPROCS=2 GOTOOLCHAIN=local GOFLAGS=-p=1
export GOPATH="${GOPATH:-$HOME/gopath}" GOCACHE="${GOCACHE:-$HOME/go-cache}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$HOME/gradle-cache}"
go version
go test -timeout 3m ./...
go vet ./...
if [[ "${CHAMELEON_RELEASE_BUILD:-false}" == true ]]; then
  out="/srv/chameleon/ci/artifacts/$(git rev-parse HEAD)"
  mkdir -p "$out"
  python3 - "$out" <<'PY'
import pathlib,sys,urllib.request,zipfile,hashlib,io
out=pathlib.Path(sys.argv[1])
with urllib.request.urlopen("https://www.wintun.net/builds/wintun-0.14.1.zip",timeout=30) as r:
    data=r.read(2*1024*1024)
with zipfile.ZipFile(io.BytesIO(data)) as z:
    dll=z.read("wintun/bin/amd64/wintun.dll")
    if hashlib.sha256(dll).hexdigest()!="e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce":
        raise SystemExit("Wintun trust gate failed")
    (out/"wintun.dll").write_bytes(dll)
    (out/"WINTUN-LICENSE.txt").write_bytes(z.read("wintun/LICENSE.txt"))
PY
  scripts/build-free-product.sh "$out"
  echo "Unsigned build files remain in the private build-host CI artifact directory."
  echo "Signing and publication require independent root-controlled verification."
fi
