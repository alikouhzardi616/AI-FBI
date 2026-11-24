#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
if ! command -v buildozer >/dev/null 2>&1; then
    echo "Buildozer is required. Install it in a Linux environment with Android SDK/NDK support." >&2
    exit 1
fi

buildozer android debug
echo "APK output is in bin/."
