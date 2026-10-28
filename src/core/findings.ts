import type { ArtifactReport } from './analyze';

export type Severity = 'error' | 'warn' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
}

const PACKAGE_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;

/** Rough "now" injection point so tests are deterministic. */
export const clock = { now: () => new Date() };

export function buildFindings(r: ArtifactReport, manifestErrors: string[]): Finding[] {
  const f: Finding[] = [];
  const add = (id: string, severity: Severity, title: string, detail: string) => f.push({ id, severity, title, detail });

  for (const m of manifestErrors) add('manifest-unreadable', 'error', 'Manifest could not be read', m);

  const pkg = r.manifest.packageName;
  if (!manifestErrors.length && !pkg) add('no-package', 'error', 'No package name', 'The manifest has no package attribute.');
  if (pkg && !PACKAGE_RE.test(pkg)) {
    add('package-format', 'warn', 'Unusual package name', `"${pkg}" is not a Java-style name with at least two segments; the console expects one.`);
  }

  if (r.kind === 'apk-set') {
    add('apk-set', 'info', 'Split APK set', `Read ${r.children.length} APK(s) from the set. The base APK's package and key are shown; register the package once.`);
    const keys = new Set(r.children.map((c) => c.currentCert?.sha256).filter(Boolean));
    if (keys.size > 1) {
      add('split-key-mismatch', 'error', 'Splits are signed with different keys', 'Every APK in a set must be signed with the same key or Android will refuse the install.');
    }
    return f;
  }

  if (r.signers.length === 0) {
    add('unsigned', 'error', 'Not signed', 'No v1 JAR signature or APK Signing Block was found. There is no key fingerprint to register.');
    return f;
  }

  const current = r.currentCert;
  if (r.kind === 'aab') {
    add(
      'aab-upload-key',
      'warn',
      'App bundle: this is probably your upload key',
      'An .aab is signed with your upload key. If you use Play App Signing, devices see Google\'s app signing key instead. Copy that SHA-256 from Play Console › Test and release › App integrity, or analyse an APK downloaded from Play or built with bundletool.',
    );
  }

  if (current?.isDebug) {
    add('debug-key', 'error', 'Signed with the Android debug key', 'This build uses the SDK debug keystore (CN=Android Debug). Register your release key, not the debug key that every Android Studio install has.');
  }
  if (r.manifest.debuggable) add('debuggable', 'warn', 'android:debuggable="true"', 'This is a debuggable build. Use a release build for distribution and for proof-of-ownership uploads.');
  if (r.manifest.testOnly) add('test-only', 'warn', 'android:testOnly="true"', 'Test-only APKs cannot be installed normally and are rejected by most stores.');

  if (r.kind === 'apk') {
    const has = (s: string) => r.schemes.includes(s as never);
    if (has('v1') && !has('v2') && !has('v3') && !has('v3.1')) {
      add('v1-only', 'warn', 'Only v1 (JAR) signing', 'Android 11+ requires v2 or newer for apps targeting API 30+. Enable v2 signing.');
    }
    if (!has('v1') && (r.manifest.minSdk ?? 0) > 0 && (r.manifest.minSdk ?? 0) < 24) {
      add('missing-v1', 'warn', 'No v1 signature but minSdk < 24', 'Devices on Android 6 and older only understand v1 signatures and will refuse this APK.');
    }
    for (const i of r.integrity) {
      if (i.status === 'failed') add('integrity-failed', 'error', `${i.scheme} signature check failed`, i.detail);
    }
  }

  // Scheme consistency: older schemes may legitimately use an earlier key in the rotation lineage.
  const lineageShas = new Set(r.lineage.map((l) => l.cert.sha256));
  const blockShas = new Set(r.signers.map((s) => s.cert.sha256));
  if (blockShas.size > 1) {
    const unexplained = [...blockShas].filter((s) => !lineageShas.has(s));
    if (r.lineage.length === 0 || unexplained.length > 0) {
      const v2Count = r.signers.filter((s) => s.scheme === 'v2').length;
      if (v2Count > 1) {
        add('multiple-signers', 'warn', 'Multiple signers', 'This APK is signed by more than one key. Each key that should be trusted for this package needs registering.');
      } else {
        add('scheme-key-mismatch', 'warn', 'Signature schemes use different keys', 'The v1/v2/v3 signatures carry different certificates and no rotation lineage explains it. Check the build\'s signing config.');
      }
    }
  }

  if (r.lineage.length > 1) {
    add(
      'rotated',
      'info',
      `Key rotation: ${r.lineage.length} keys in lineage`,
      'Devices on Android 9+ verify with the newest key; older devices use the original key. Register the current key, and add earlier keys too if builds signed with them are still out there.',
    );
  }

  if (current) {
    const pk = current.publicKey;
    if (pk.algorithm === 'RSA' && (pk.bits ?? 0) < 2048) add('weak-key', 'warn', `RSA ${pk.bits}-bit key`, 'Keys under 2048 bits are considered weak. You can\'t change the key without rotation, so plan a v3 rotation.');
    if (pk.algorithm === 'DSA') add('dsa-key', 'info', 'DSA signing key', 'DSA keys still work but the browser cannot verify DSA signatures. Use apksigner for a full check.');
    if (current.notAfter && new Date(current.notAfter) < clock.now()) {
      add('cert-expired', 'info', 'Certificate validity date has passed', `Not after ${current.notAfter.slice(0, 10)}. Android ignores app-signing certificate expiry, so the fingerprint is still the one to register.`);
    }
  }

  const exact = r.proofFiles.find((p) => p.path === 'assets/adi-registration.properties');
  const misplaced = r.proofFiles.filter((p) => p.path !== 'assets/adi-registration.properties');
  if (exact) add('proof-present', 'info', 'Contains a proof-of-ownership snippet', `assets/adi-registration.properties holds "${exact.text.trim()}". This is a verification APK; do not ship it to users unless you mean to.`);
  for (const m of misplaced) {
    add('proof-misplaced', 'error', 'Snippet file in the wrong place', `Found ${m.path}. The console only reads assets/adi-registration.properties (src/main/assets in a Gradle project).`);
  }
  return f;
}
