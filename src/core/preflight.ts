import { normalizeFingerprint } from './bytes';
import type { ArtifactReport } from './analyze';

export interface PreflightInput {
  packageName: string;
  fingerprint: string;
  /** The snippet copied from the console / API verificationToken. Optional. */
  token?: string;
}

export interface Check {
  id: string;
  status: 'pass' | 'fail' | 'warn' | 'skip';
  title: string;
  detail: string;
}

export interface PreflightResult {
  ready: boolean;
  checks: Check[];
}

/**
 * Checks an APK built for the proof-of-ownership step before it is uploaded:
 * right package, snippet at the exact path with the exact contents, and signed by the key being registered.
 */
export function preflight(r: ArtifactReport, input: PreflightInput): PreflightResult {
  const checks: Check[] = [];
  const add = (id: string, status: Check['status'], title: string, detail: string) => checks.push({ id, status, title, detail });

  if (r.findings.some((f) => f.id === 'parse-error')) {
    add('readable', 'fail', 'File is readable', r.findings[0].detail);
    return { ready: false, checks };
  }

  if (r.kind === 'apk') add('kind', 'pass', 'It is an APK', 'The console takes a signed APK for this step.');
  else add('kind', 'fail', 'It is an APK', r.kind === 'aab' ? 'This is an app bundle. Upload a signed .apk built from it (for example with bundletool build-apks --mode=universal).' : 'Upload the single universal or base .apk, not an APK set.');

  const want = input.packageName.trim();
  const got = r.manifest.packageName;
  if (!want) add('package', 'skip', 'Package name matches', 'Enter the package name you are registering.');
  else if (got === want) add('package', 'pass', 'Package name matches', got);
  else add('package', 'fail', 'Package name matches', `APK is "${got ?? 'unknown'}", registering "${want}". A minimal project with the same applicationId is fine.`);

  const exact = r.proofFiles.find((p) => p.path === 'assets/adi-registration.properties');
  if (!exact) {
    const elsewhere = r.proofFiles.map((p) => p.path).join(', ');
    add('snippet-path', 'fail', 'assets/adi-registration.properties is present', elsewhere ? `Found it at ${elsewhere} instead. Put it in src/main/assets/.` : 'The file is missing. Create app/src/main/assets/adi-registration.properties and paste the snippet.');
  } else {
    add('snippet-path', 'pass', 'assets/adi-registration.properties is present', `Contents: "${exact.text.trim()}"`);
    const token = (input.token ?? '').trim();
    const text = exact.text;
    if (!token) add('snippet-match', 'skip', 'Snippet matches the console', 'Paste the snippet from the console to compare.');
    else if (text.trim() === token) {
      const extra = text !== token && text !== `${token}\n`;
      if (text.charCodeAt(0) === 0xfeff) add('snippet-match', 'warn', 'Snippet matches the console', 'The file starts with a byte-order mark. Save it as plain UTF-8 without BOM to be safe.');
      else if (extra) add('snippet-match', 'warn', 'Snippet matches the console', 'Matches, but the file has extra whitespace or Windows line endings around the snippet. Consider saving it with exactly the snippet.');
      else add('snippet-match', 'pass', 'Snippet matches the console', 'Exact match.');
    } else if (text.includes(token)) {
      add('snippet-match', 'warn', 'Snippet matches the console', 'The snippet is in the file, but there is other text too. Paste only the snippet.');
    } else add('snippet-match', 'fail', 'Snippet matches the console', `File has "${text.trim().slice(0, 80)}", the console snippet is "${token.slice(0, 80)}". Snippets are tied to one package and key; copy it again.`);
  }

  const fp = normalizeFingerprint(input.fingerprint);
  if (!input.fingerprint.trim()) add('key', 'skip', 'Signed with the key being registered', 'Enter the SHA-256 fingerprint you added in the console.');
  else if (!fp) add('key', 'fail', 'Signed with the key being registered', 'That is not a SHA-256 fingerprint (64 hex characters, colons optional).');
  else {
    const signing = r.signers.filter((s) => s.cert.sha256 === fp);
    const inLineage = r.lineage.some((l) => l.cert.sha256 === fp);
    if (signing.length) {
      const schemes = [...new Set(signing.map((s) => s.scheme))].join(', ');
      add('key', 'pass', 'Signed with the key being registered', `Matched by the ${schemes} signature.`);
    } else if (inLineage) {
      add('key', 'fail', 'Signed with the key being registered', 'That key only appears in the rotation lineage. Sign the proof APK directly with that key.');
    } else {
      const cur = r.currentCert?.sha256;
      add('key', 'fail', 'Signed with the key being registered', `This APK is signed with ${cur ? cur.slice(0, 16) + '…' : 'no key'}. Re-sign it with the private key for the fingerprint you entered.`);
    }
  }

  const failed = r.integrity.filter((i) => i.status === 'failed');
  if (r.kind === 'apk') {
    if (failed.length) add('integrity', 'fail', 'Signature is intact', failed.map((i) => `${i.scheme}: ${i.detail}`).join('; '));
    else if (r.integrity.some((i) => i.status === 'verified')) add('integrity', 'pass', 'Signature is intact', 'v2/v3 signature and whole-file digest verified in your browser.');
    else add('integrity', 'warn', 'Signature is intact', 'Only a v1 (or DSA) signature, which this tool does not verify cryptographically. Run apksigner verify to be sure.');
  }

  for (const f of r.findings) {
    if (f.id === 'debug-key') add('debug', 'fail', 'Not the debug key', f.detail);
  }

  const ready = !checks.some((c) => c.status === 'fail') && checks.every((c) => c.status !== 'skip' || c.id === 'snippet-match');
  return { ready, checks };
}
