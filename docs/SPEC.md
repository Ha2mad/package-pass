# Package Pass: spec

## Problem
Android developer verification is live. Since 30 September 2026, on certified devices (Android 7+) in Brazil, Indonesia, Singapore and Thailand, apps installed through participating stores (Google Play, Galaxy Store, HONOR, OPPO, Xiaomi GetApps, vivo, Palm Store) must come from a verified developer. Google plans to roll this out globally in 2027, after which installing apps from unverified developers outside those stores needs the "advanced flow" or ADB.

Developers must register **every package name** and **every SHA-256 signing-key fingerprint** that signs it in the Android Developer Console. Existing package names also need a proof-of-ownership APK (`assets/adi-registration.properties` containing a console snippet, signed with the key).

Studios that ship through more than one channel (Play plus Galaxy Store, F-Droid, OEM stores, direct APK, enterprise) have several keys per app and many apps. Today's tools are single-file fingerprint viewers or `apksigner` / `keytool` / `aapt2` from the Android SDK. None of them inventories a whole release folder, groups keys across packages, explains rotation and upload keys, or checks a proof APK before upload.

## Users
Indie and small-studio Android developers, F-Droid maintainers, agencies with many client apps, and enterprise app teams preparing for verification.

## Scope
* A static web app (no backend) plus a Node CLI built from the same core.
* Inputs: `.apk`, `.aab`, `.apks`, `.xapk` (multiple files at once, directories in the CLI).
* All parsing is done in TypeScript in the browser: ZIP, binary AXML, AAB protobuf manifest, APK Signing Block v2/v3/v3.1, JAR v1 PKCS#7, X.509 DER.

## Acceptance criteria
1. For each artifact, show package name, versionName/versionCode, minSdk/targetSdk, the signature schemes present, and the SHA-256 fingerprint of the key Android uses for that APK (v3.1 > v3 > v2 > v1). The fingerprint is shown in colon format and in API format (lowercase hex), and both can be copied.
2. v2/v3 signatures are cryptographically verified in the browser (signed-data signature plus whole-file chunked content digest). Tampering with a single byte of a fixture makes verification fail.
3. Key-rotation lineage (v3 proof-of-rotation) is listed, and earlier keys are marked as needing registration for devices that still have old installs.
4. Findings flag: debug keys, debuggable/testOnly builds, AAB upload keys (with Play App Signing guidance), v1-only APKs, missing v1 with minSdk < 24, scheme key mismatches, multiple signers, weak RSA (< 2048), DSA, expired certs, split key mismatches in APK sets, and proof snippets left in a build or placed at the wrong path.
5. The registration plan groups everything by package. Each row has key, role, certificate subject and source files. It calls out keys shared across packages (prove ownership once). Debug keys are excluded from the registrable key count.
6. Exports: CSV (formula-injection safe), JSON, and a review-first bash script for the Developer Console API that does a dry run unless `RUN=1` and reads the token from the environment.
7. The proof APK preflight checks APK type, package match, snippet path, snippet match (optional), signing with the entered fingerprint, and signature integrity. It returns a single Ready / Not ready verdict.
8. No network requests other than loading the app itself; a strict CSP is set in `index.html`.
9. CLI: `scan` (human output, `--json`, `--csv`, `--plan-json`, `--script`, `--fail-on`) and `preflight` with exit codes suitable for CI.
10. Tests use real fixtures signed by Android's own `apksig`, with expected fingerprints from `keytool`. Lint, typecheck, tests and build pass in CI.
