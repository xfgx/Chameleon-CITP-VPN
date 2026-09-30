#!/usr/bin/env bash
set -euo pipefail
# Builds are permitted only on the owner's explicitly marked RU/build-host machines.
node="$(cat /etc/chameleon/build-node 2>/dev/null || true)"
[[ "$node" == build-host || "$node" == ru ]] || { echo "Build node must be build-host or RU" >&2; exit 1; }
[[ "$(id -u)" != 0 ]] || { echo "Compile as the isolated build account, not root" >&2; exit 1; }
out="${1:?private build output directory required}"
mkdir -p "$out"
export PATH="/opt/chameleon-toolchain/go/bin:/opt/chameleon-toolchain/gradle-8.7/bin:$PATH"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
export ANDROID_HOME="/opt/chameleon-toolchain/android-sdk" ANDROID_SDK_ROOT="$ANDROID_HOME"
export GOMAXPROCS=2 GOFLAGS=-p=1 GOTOOLCHAIN=local TZ=UTC LC_ALL=C.UTF-8
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
test -n "${GOPATH:?separate GOPATH required}"
test -n "${GOCACHE:?separate GOCACHE required}"
test -n "${GRADLE_USER_HOME:?separate Gradle cache required}"
[[ "$(go version)" == *go1.26.6* ]] || { echo "Go 1.26.6 required"; exit 1; }
go test ./...
go vet ./cmd/ks-admin ./cmd/vpn-web ./cmd/vpn-observer ./internal/activation ./internal/clientactivation ./internal/telemetry ./cmd/chamd ./mobilecore
for name in ks-admin vpn-web vpn-observer license-keygen; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -o "$out/$name" "./cmd/$name"
done
# The trusted Wintun DLL/notice files are supplied separately, never arbitrary DLLs.
test -f "$out/wintun.dll"
checksum="$(sha256sum "$out/wintun.dll" | cut -d' ' -f1)"
[[ "$checksum" == e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce ]] || { echo "Unverified Wintun DLL"; exit 1; }
# Shared Windows-only path includes native SCM setup, icon and installer checks.
bash scripts/build-windows-product.sh "$out"
go install golang.org/x/mobile/cmd/gomobile
go install golang.org/x/mobile/cmd/gobind
export PATH="$GOPATH/bin:$PATH"
gomobile init
mkdir -p android/app/libs
gomobile bind -target=android/arm,android/arm64 -androidapi=23 -trimpath \
  -o android/app/libs/mobilecore.aar ./mobilecore
gradle -p android --no-daemon --max-workers=2 :app:assembleRelease :app:lintRelease
cp android/app/build/outputs/apk/release/app-release-unsigned.apk "$out/Chameleon-4.3.0-android-unsigned.apk"
cp packaging/{THIRD-PARTY-NOTICES.txt,CORRESPONDING-SOURCE.txt} "$out/"
git rev-parse HEAD > "$out/source-commit.txt"
go list -m all > "$out/GO-MODULES.txt"
python3 - "$out" "$node" <<'PY'
import hashlib,json,os,pathlib,subprocess,sys
out=pathlib.Path(sys.argv[1])
names=["ks-admin","vpn-web","vpn-observer","license-keygen","Chameleon.exe",
       "wintun.dll","broker-setup.exe","chameleon.ico","Chameleon-4.3.0-android-unsigned.apk",
       "Chameleon-4.3.0-windows-setup.exe","GO-MODULES.txt",
       "THIRD-PARTY-NOTICES.txt","CORRESPONDING-SOURCE.txt"]
def digest(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(131072),b""):h.update(b)
    return h.hexdigest()
receipt={"version":1,"build_node":sys.argv[2],
         "source_commit":subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
         "source_date_epoch":int(os.environ["SOURCE_DATE_EPOCH"]),
         "toolchain":{"go":subprocess.check_output(["go","version"],text=True).strip(),
                      "jdk_major":17,"gradle":"8.7","android_sdk":34,
                      "android_ndk":"26.1.10909125","wintun":"0.14.1"},
         "source_inputs":{n:digest(pathlib.Path(n)) for n in ["go.mod","go.sum"]},
         "unsigned_artifacts":{n:{"bytes":(out/n).stat().st_size,
                                   "sha256":digest(out/n)} for n in names}}
(out/"BUILD-RECEIPT.json").write_text(json.dumps(receipt,indent=2)+"\n")
PY
echo "Compilation complete on $node. APK signing/publication is a separate root-controlled step."
