import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  analyzeSafely,
  buildPlan,
  colonHex,
  planToApiScript,
  planToCsv,
  planToJson,
  preflight,
  ROLE_LABEL,
  type ArtifactReport,
} from './core';

const VERSION = '1.0.0';
const EXT = /\.(apk|aab|apks|xapk)$/i;

const HELP = `package-pass ${VERSION}: prepare Android apps for developer verification

Usage:
  package-pass scan <file-or-dir>... [--json] [--csv FILE] [--plan-json FILE] [--script FILE] [--fail-on error|warn]
  package-pass preflight <proof.apk> --package NAME --fingerprint SHA256 [--token SNIPPET | --token-file FILE]

scan       Reads package names and signing-key SHA-256 fingerprints from .apk/.aab/.apks/.xapk files
           (directories are searched recursively), prints findings and a per-package key plan.
preflight  Checks a proof-of-ownership APK before you upload it to the Android Developer Console.

Everything runs locally; nothing is uploaded.`;

function collect(paths: string[]): string[] {
  const out: string[] = [];
  const walk = (p: string) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const name of readdirSync(p).sort()) {
        if (name === 'node_modules' || name.startsWith('.')) continue;
        const child = join(p, name);
        if (statSync(child).isDirectory() || EXT.test(name)) walk(child);
      }
    } else out.push(p);
  };
  paths.forEach(walk);
  return out;
}

const mark = { error: '✖', warn: '!', info: 'i' } as const;

function printReport(r: ArtifactReport): void {
  const m = r.manifest;
  console.log(`\n${r.fileName}  [${r.kind}]`);
  if (m.packageName) console.log(`  package     ${m.packageName}  ${m.versionName ?? ''}${m.versionCode ? ` (${m.versionCode})` : ''}`);
  if (r.currentCert) {
    console.log(`  key SHA-256 ${colonHex(r.currentCert.sha256)}`);
    console.log(`  subject     ${r.currentCert.subject}`);
  }
  if (r.schemes.length) console.log(`  schemes     ${r.schemes.join(', ')}`);
  for (const i of r.integrity) console.log(`  ${i.scheme.padEnd(11)} ${i.status}`);
  for (const f of r.findings) console.log(`  ${mark[f.severity]} ${f.title}: ${f.detail}`);
}

async function scan(files: string[], opts: Record<string, string | boolean | undefined>): Promise<number> {
  const paths = collect(files);
  if (!paths.length) {
    console.error('No .apk/.aab/.apks/.xapk files found.');
    return 2;
  }
  const reports: ArtifactReport[] = [];
  for (const p of paths) reports.push(await analyzeSafely(basename(p), new Uint8Array(readFileSync(p))));
  const plan = buildPlan(reports);
  if (opts.csv) writeFileSync(String(opts.csv), planToCsv(plan));
  if (opts['plan-json']) writeFileSync(String(opts['plan-json']), planToJson(plan));
  if (opts.script) writeFileSync(String(opts.script), planToApiScript(plan), { mode: 0o755 });

  if (opts.json) {
    console.log(JSON.stringify(reports, null, 2));
  } else {
    reports.forEach(printReport);
    console.log('\nRegistration plan');
    for (const p of plan.packages) {
      console.log(`  ${p.packageName}`);
      for (const k of p.keys) console.log(`    ${colonHex(k.sha256)}  ${ROLE_LABEL[k.role]}`);
    }
    const shared = plan.keyGroups.filter((g) => g.packages.length > 1);
    for (const g of shared) {
      console.log(`  Key ${g.sha256.slice(0, 16)}… signs ${g.packages.length} packages: prove ownership once, the rest skip the proof step.`);
    }
  }
  const failOn = opts['fail-on'];
  const sev = reports.flatMap((r) => r.findings.map((f) => f.severity));
  if (failOn === 'error' && sev.includes('error')) return 1;
  if (failOn === 'warn' && (sev.includes('error') || sev.includes('warn'))) return 1;
  return 0;
}

async function runPreflight(file: string, opts: Record<string, string | boolean | undefined>): Promise<number> {
  const r = await analyzeSafely(basename(file), new Uint8Array(readFileSync(file)));
  const token = opts['token-file'] ? readFileSync(String(opts['token-file']), 'utf8') : (opts.token as string | undefined);
  const res = preflight(r, { packageName: String(opts.package ?? ''), fingerprint: String(opts.fingerprint ?? ''), token });
  const icon = { pass: '✔', fail: '✖', warn: '!', skip: '-' } as const;
  console.log(`Preflight for ${r.fileName}`);
  for (const c of res.checks) console.log(`  ${icon[c.status]} ${c.title}: ${c.detail}`);
  console.log(res.ready ? '\nReady to upload.' : '\nNot ready: fix the items marked ✖ (and fill any skipped inputs).');
  return res.ready ? 0 : 1;
}

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: 'boolean' },
      csv: { type: 'string' },
      'plan-json': { type: 'string' },
      script: { type: 'string' },
      'fail-on': { type: 'string' },
      package: { type: 'string' },
      fingerprint: { type: 'string' },
      token: { type: 'string' },
      'token-file': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  if (values.version) {
    console.log(VERSION);
    return 0;
  }
  const [cmd, ...rest] = positionals;
  if (values.help || !cmd) {
    console.log(HELP);
    return values.help ? 0 : 2;
  }
  if (cmd === 'scan') return scan(rest, values);
  if (cmd === 'preflight' && rest.length === 1) return runPreflight(rest[0], values);
  console.error(HELP);
  return 2;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: Error) => {
    console.error(`package-pass: ${err.message}`);
    process.exit(2);
  },
);
