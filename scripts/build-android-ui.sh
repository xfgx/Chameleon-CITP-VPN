#!/usr/bin/env bash
set -euo pipefail
node="$(cat /etc/chameleon/build-node 2>/dev/null || true)"
[[ "$node" == build-host || "$node" == ru ]] || { echo 'Approved build node required'; exit 1; }
[[ "$(id -u)" != 0 ]] || { echo 'Build as isolated account'; exit 1; }
cd "$(dirname "$0")/.."
out="${1:?absolute private output directory required}"
[[ "$out" == /* ]] || exit 1
: "${GRADLE_USER_HOME:?isolated cache required}"
mkdir -p "$out"
# Deliberately preserve the working native VPN data plane for this UI release.
[[ "$(sha256sum android/app/libs/mobilecore.aar | cut -d' ' -f1)" == 8301b3eb8a5b284081a75ef4de62598494a23cbeaae3de086be6a5d6efc1f1fa ]] || { echo 'Native AAR differs from approved baseline'; exit 1; }
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=/opt/chameleon-toolchain/android-sdk ANDROID_SDK_ROOT=/opt/chameleon-toolchain/android-sdk
/opt/chameleon-toolchain/gradle-8.7/bin/gradle -p android --offline --no-daemon --max-workers=1 -Dorg.gradle.jvmargs='-Xmx900m -Dfile.encoding=UTF-8' -Pkotlin.compiler.execution.strategy=in-process :app:assembleRelease :app:lintRelease
cp android/app/build/outputs/apk/release/app-release-unsigned.apk "$out/Chameleon-4.3.0-android-unsigned.apk"
echo 'Unsigned build ready. Release signing is a separate protected operation.'
