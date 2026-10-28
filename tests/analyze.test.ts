import { describe, expect, it } from 'vitest';
import { analyzeSafely } from '../src/core';
import { analyze, expected, fixture } from './helpers';

const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

describe('APK analysis', () => {
  it('reads package, versions and a v1+v2 RSA signer', async () => {
    const r = await analyze('alpha-direct.apk');
    expect(r.kind).toBe('apk');
    expect(r.manifest).toMatchObject({ packageName: 'com.axenova.alpha', versionCode: '12', versionName: '1.4.0', minSdk: 21, targetSdk: 35, debuggable: false });
    expect(r.schemes).toEqual(['v1', 'v2']);
    expect(r.currentCert?.sha256).toBe(expected.release);
    expect(r.signers.every((s) => s.cert.sha256 === expected.release)).toBe(true);
    expect(r.currentCert?.subjectCN).toBe('Axenova Release');
    expect(r.currentCert?.publicKey).toEqual({ algorithm: 'RSA', bits: 2048 });
    expect(r.currentCert?.signatureAlgorithm).toBe('SHA384withRSA');
    expect(r.integrity).toEqual([{ scheme: 'v2', status: 'verified', detail: expect.any(String) }]);
    expect(r.findings.filter((f) => f.severity !== 'info')).toEqual([]);
  });

  it('reads store re-signed v2+v3 APKs', async () => {
    const r = await analyze('alpha-repo.apk');
    expect(r.schemes).toEqual(['v2', 'v3']);
    expect(r.currentCert?.sha256).toBe(expected.store);
    expect(r.integrity.map((i) => i.status)).toEqual(['verified', 'verified']);
    const v3 = r.signers.find((s) => s.scheme === 'v3');
    expect(v3?.minSdk).toBe(24);
  });

  it('follows a v3 rotation lineage and picks the newest key', async () => {
    const r = await analyze('beta-rotated.apk');
    expect(r.manifest.packageName).toBe('com.axenova.beta');
    expect(r.currentCert?.sha256).toBe(expected.rotated);
    expect(r.lineage.map((l) => l.cert.sha256)).toEqual([expected.release, expected.rotated]);
    expect(r.signers.find((s) => s.scheme === 'v2')?.cert.sha256).toBe(expected.release);
    expect(r.currentCert?.publicKey.bits).toBe(3072);
    expect(ids(r)).toContain('rotated');
    expect(ids(r)).not.toContain('scheme-key-mismatch');
    expect(r.integrity.every((i) => i.status === 'verified')).toBe(true);
  });

  it('verifies ECDSA signers', async () => {
    const r = await analyze('gamma-ec.apk');
    expect(r.currentCert?.sha256).toBe(expected.ec);
    expect(r.currentCert?.publicKey).toEqual({ algorithm: 'EC', curve: 'P-256', bits: 256 });
    expect(r.integrity.map((i) => i.status)).toEqual(['verified', 'verified']);
  });

  it('flags debug keys and debuggable builds', async () => {
    const r = await analyze('debug-signed.apk');
    expect(r.currentCert?.isDebug).toBe(true);
    expect(r.currentCert?.sha256).toBe(expected.debug);
    expect(ids(r)).toEqual(expect.arrayContaining(['debug-key', 'debuggable']));
  });

  it('finds the proof-of-ownership snippet', async () => {
    const r = await analyze('alpha-proof.apk');
    expect(r.proofFiles).toEqual([{ path: 'assets/adi-registration.properties', text: 'FIXTURE0TOKEN0ALPHA0000000\n' }]);
    expect(ids(r)).toContain('proof-present');
  });

  it('detects tampering after signing', async () => {
    const bytes = fixture('alpha-direct.apk').slice();
    // Flip a byte inside the first local file's data (before the signing block).
    bytes[40] ^= 0xff;
    const r = await analyzeSafely('tampered.apk', bytes);
    const v2 = r.integrity.find((i) => i.scheme === 'v2');
    expect(v2?.status).toBe('failed');
    expect(ids(r)).toContain('integrity-failed');
  });
});

describe('bundles and sets', () => {
  it('reads the proto manifest and upload key from an .aab', async () => {
    const r = await analyze('alpha.aab');
    expect(r.kind).toBe('aab');
    expect(r.manifest).toMatchObject({ packageName: 'com.axenova.alpha', versionCode: '12', versionName: '1.4.0', minSdk: 21 });
    expect(r.schemes).toEqual(['v1']);
    expect(r.currentCert?.sha256).toBe(expected.upload);
    expect(ids(r)).toContain('aab-upload-key');
  });

  it('reads the base APK inside an .apks set', async () => {
    const r = await analyze('alpha.apks');
    expect(r.kind).toBe('apk-set');
    expect(r.children).toHaveLength(1);
    expect(r.manifest.packageName).toBe('com.axenova.alpha');
    expect(r.currentCert?.sha256).toBe(expected.release);
  });

  it('returns an error report for non-ZIP input', async () => {
    const r = await analyzeSafely('notes.txt', new TextEncoder().encode('hello'));
    expect(r.findings[0].id).toBe('parse-error');
    expect(r.currentCert).toBeNull();
  });
});
