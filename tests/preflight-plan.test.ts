import { describe, expect, it } from 'vitest';
import { buildPlan, colonHex, normalizeFingerprint, planToApiScript, planToCsv, planToJson, preflight } from '../src/core';
import { analyze, expected } from './helpers';

const TOKEN = 'FIXTURE0TOKEN0ALPHA0000000';
const status = (r: ReturnType<typeof preflight>) => Object.fromEntries(r.checks.map((c) => [c.id, c.status]));

describe('fingerprint helpers', () => {
  it('normalises colon, spaced and lower-case input', () => {
    const fp = expected.release;
    expect(normalizeFingerprint(colonHex(fp))).toBe(fp);
    expect(normalizeFingerprint(fp.toLowerCase())).toBe(fp);
    expect(normalizeFingerprint(colonHex(fp).replace(/:/g, ' '))).toBe(fp);
    expect(normalizeFingerprint('abc')).toBeNull();
  });
});

describe('proof APK preflight', () => {
  it('passes a correct proof APK', async () => {
    const r = await analyze('alpha-proof.apk');
    const res = preflight(r, { packageName: 'com.axenova.alpha', fingerprint: colonHex(expected.release), token: TOKEN });
    expect(status(res)).toEqual({ kind: 'pass', package: 'pass', 'snippet-path': 'pass', 'snippet-match': 'pass', key: 'pass', integrity: 'pass' });
    expect(res.ready).toBe(true);
  });

  it('fails on wrong key, wrong package and wrong token', async () => {
    const r = await analyze('alpha-proof.apk');
    const res = preflight(r, { packageName: 'com.axenova.beta', fingerprint: expected.store, token: 'SOMETHINGELSE' });
    expect(status(res)).toMatchObject({ package: 'fail', 'snippet-match': 'fail', key: 'fail' });
    expect(res.ready).toBe(false);
  });

  it('fails when the snippet is missing', async () => {
    const r = await analyze('alpha-direct.apk');
    const res = preflight(r, { packageName: 'com.axenova.alpha', fingerprint: expected.release, token: TOKEN });
    expect(status(res)['snippet-path']).toBe('fail');
    expect(res.ready).toBe(false);
  });

  it('rejects bundles and keys that only appear in the lineage', async () => {
    const aab = preflight(await analyze('alpha.aab'), { packageName: 'com.axenova.alpha', fingerprint: expected.upload });
    expect(status(aab).kind).toBe('fail');
    const beta = await analyze('beta-rotated.apk');
    // The old key signs v2 directly, so it passes; a key that is neither signer nor lineage fails.
    expect(status(preflight(beta, { packageName: 'com.axenova.beta', fingerprint: expected.release })).key).toBe('pass');
    expect(status(preflight(beta, { packageName: 'com.axenova.beta', fingerprint: expected.ec })).key).toBe('fail');
  });

  it('fails debug-signed APKs', async () => {
    const res = preflight(await analyze('debug-signed.apk'), { packageName: 'com.axenova.debugapp', fingerprint: expected.debug });
    expect(status(res).debug).toBe('fail');
  });
});

describe('registration plan', () => {
  const load = () =>
    Promise.all(['alpha-direct.apk', 'alpha-repo.apk', 'alpha.aab', 'beta-rotated.apk', 'gamma-ec.apk', 'debug-signed.apk'].map(analyze));

  it('groups keys per package with roles', async () => {
    const plan = buildPlan(await load());
    expect(plan.packages.map((p) => p.packageName)).toEqual(['com.axenova.alpha', 'com.axenova.beta', 'com.axenova.debugapp', 'com.axenova.gamma']);
    const alpha = plan.packages[0];
    expect(alpha.keys.map((k) => [k.sha256, k.role])).toEqual(
      [
        [expected.release, 'signing'],
        [expected.store, 'signing'],
        [expected.upload, 'upload'],
      ].sort((a, b) => (a[1] === b[1] ? a[0].localeCompare(b[0]) : a[1] === 'signing' ? -1 : 1)),
    );
    const beta = plan.packages[1];
    expect(beta.keys.map((k) => k.role)).toEqual(['signing', 'earlier-rotation']);
    expect(plan.packages[2].keys[0].role).toBe('debug');
  });

  it('finds keys shared across packages and skips debug keys', async () => {
    const plan = buildPlan(await load());
    expect(plan.keyGroups[0]).toMatchObject({ sha256: expected.release, packages: ['com.axenova.alpha', 'com.axenova.beta'] });
    expect(plan.keyGroups.some((g) => g.sha256 === expected.debug)).toBe(false);
  });

  it('exports CSV, JSON and a dry-run API script', async () => {
    const plan = buildPlan(await load());
    const csv = planToCsv(plan);
    expect(csv.split('\r\n')[0]).toBe('"package_name","sha256_fingerprint","sha256_api","role","certificate_subject","valid_until","source_files"');
    expect(csv).toContain(colonHex(expected.store));
    const json = JSON.parse(planToJson(plan, '2026-10-28T00:00:00Z'));
    expect(json.packages[0].keys[0].certificateFingerprintSha256).toMatch(/^[0-9a-f]{64}$/);
    const script = planToApiScript(plan, '2026-10-28T00:00:00Z');
    expect(script).toContain(`add_key com.axenova.gamma ${expected.ec.toLowerCase()}`);
    expect(script).toContain(`# add_key com.axenova.alpha ${expected.upload.toLowerCase()}`);
    expect(script).toContain(`# not registering ${expected.debug.toLowerCase()}`);
    expect(script).toContain('if [ "${RUN:-0}" != "1" ]');
  });

  it('neutralises formula-like cells in CSV', async () => {
    const plan = buildPlan([await analyze('alpha-direct.apk')]);
    plan.packages[0].keys[0].cert = { ...plan.packages[0].keys[0].cert, subject: '=HYPERLINK("x")' };
    expect(planToCsv(plan)).toContain(`"'=HYPERLINK(""x"")"`);
  });
});
