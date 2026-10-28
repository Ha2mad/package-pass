#!/usr/bin/env bash
# Regenerates the signed test fixtures in tests/fixtures.
# Needs: JDK 17+ (java, keytool, jarsigner), python3, and a tools dir containing
#   aapt2        (from com.android.tools.build:aapt2:<ver>:linux on Google Maven)
#   android.jar  (from any Android SDK platform, e.g. platform-35)
#   apksig.jar   (com.android.tools.build:apksig on Google Maven)
# Usage: TOOLS=/path/to/tools scripts/fixtures/make-fixtures.sh
# All keys are throwaway fixture keys generated on the fly; nothing secret is committed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../../tests/fixtures"
TOOLS="${TOOLS:?set TOOLS to the directory with aapt2, android.jar and apksig.jar}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

key() { # name alg dname
  local extra=()
  if [ "$2" = EC ]; then extra=(-keyalg EC -groupname secp256r1); else extra=(-keyalg RSA -keysize "$2"); fi
  keytool -genkeypair -keystore "$WORK/$1.p12" -storetype PKCS12 -storepass fixture -keypass fixture \
    -alias "$1" "${extra[@]}" -validity 9000 -dname "$3" >/dev/null 2>&1
  keytool -exportcert -keystore "$WORK/$1.p12" -storepass fixture -alias "$1" -file "$WORK/$1.der" >/dev/null 2>&1
}
key release 2048 "CN=Axenova Release,O=Axenova Studio,C=PK"
key rotated 3072 "CN=Axenova Release 2026,O=Axenova Studio,C=PK"
key store 2048 "CN=Example Repo Signer,O=Example Store,C=DE"
key ec EC "CN=Axenova EC,O=Axenova Studio,C=PK"
key debug 2048 "CN=Android Debug,O=Android,C=US"
key upload 2048 "CN=Axenova Upload,O=Axenova Studio,C=PK"

manifest() { # dir package versionCode versionName debuggable
  mkdir -p "$1"
  cat > "$1/AndroidManifest.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$2"
    android:versionCode="$3" android:versionName="$4">
  <application android:label="Fixture" android:debuggable="$5" />
</manifest>
XML
}

link() { # dir out minSdk [assetsDir] [--proto-format]
  local args=(link -o "$2" -I "$TOOLS/android.jar" --manifest "$1/AndroidManifest.xml" --min-sdk-version "$3" --target-sdk-version 35)
  if [ -n "${4:-}" ]; then args+=(-A "$4"); fi
  if [ -n "${5:-}" ]; then args+=("$5"); fi
  "$TOOLS/aapt2" "${args[@]}"
}

sign() { java -cp "$TOOLS/apksig.jar" "$HERE/Sign.java" "$@"; }

manifest "$WORK/alpha" com.axenova.alpha 12 1.4.0 false
link "$WORK/alpha" "$WORK/alpha.apk" 21
sign "$WORK/alpha.apk" "$OUT/alpha-direct.apk" 21 true true false "$WORK/release.p12"
sign "$WORK/alpha.apk" "$OUT/alpha-repo.apk" 24 false true true "$WORK/store.p12"

mkdir -p "$WORK/proof-assets"
printf 'FIXTURE0TOKEN0ALPHA0000000\n' > "$WORK/proof-assets/adi-registration.properties"
link "$WORK/alpha" "$WORK/alpha-proof.apk" 24 "$WORK/proof-assets"
sign "$WORK/alpha-proof.apk" "$OUT/alpha-proof.apk" 24 false true false "$WORK/release.p12"

manifest "$WORK/beta" com.axenova.beta 7 2.0 false
link "$WORK/beta" "$WORK/beta.apk" 24
sign "$WORK/beta.apk" "$OUT/beta-rotated.apk" 24 false true true "$WORK/release.p12" "$WORK/rotated.p12"

manifest "$WORK/gamma" com.axenova.gamma 3 0.3 false
link "$WORK/gamma" "$WORK/gamma.apk" 24
sign "$WORK/gamma.apk" "$OUT/gamma-ec.apk" 24 false true true "$WORK/ec.p12"

manifest "$WORK/dbg" com.axenova.debugapp 1 1.0-debug true
link "$WORK/dbg" "$WORK/dbg.apk" 21
sign "$WORK/dbg.apk" "$OUT/debug-signed.apk" 21 true true false "$WORK/debug.p12"

# Android App Bundle: proto manifest + JAR signature with the upload key.
link "$WORK/alpha" "$WORK/alpha-proto.apk" 21 "" --proto-format
python3 - "$WORK" <<'PY'
import sys, zipfile, os
w = sys.argv[1]
src = zipfile.ZipFile(os.path.join(w, "alpha-proto.apk"))
with zipfile.ZipFile(os.path.join(w, "alpha.aab"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("BundleConfig.pb", b"")
    z.writestr("base/manifest/AndroidManifest.xml", src.read("AndroidManifest.xml"))
    z.writestr("base/resources.pb", src.read("resources.pb"))
PY
jarsigner -keystore "$WORK/upload.p12" -storetype PKCS12 -storepass fixture -keypass fixture \
  -signedjar "$OUT/alpha.aab" "$WORK/alpha.aab" upload >/dev/null 2>&1

# Split APK set (.apks) containing a base and a config split.
python3 - "$OUT" <<'PY'
import sys, zipfile, os
o = sys.argv[1]
with zipfile.ZipFile(os.path.join(o, "alpha.apks"), "w", zipfile.ZIP_STORED) as z:
    z.write(os.path.join(o, "alpha-direct.apk"), "splits/base-master.apk")
PY

# Expected fingerprints for the tests.
python3 - "$WORK" "$OUT" <<'PY'
import sys, hashlib, json, os
w, o = sys.argv[1], sys.argv[2]
names = ["release", "rotated", "store", "ec", "debug", "upload"]
fp = {n: hashlib.sha256(open(os.path.join(w, n + ".der"), "rb").read()).hexdigest().upper() for n in names}
json.dump(fp, open(os.path.join(o, "expected-fingerprints.json"), "w"), indent=2)
PY
echo "fixtures written to $OUT"
