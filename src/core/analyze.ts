import { ParseError } from './bytes';
import { emptyManifest, manifestFromElements, parseManifest, type ManifestInfo } from './axml';
import { parseProtoXml } from './protoxml';
import { pkcs7SignerCerts } from './pkcs7';
import {
  BLOCK_IDS,
  findSigningBlock,
  parseSchemeBlock,
  verifySigner,
  type BlockSigner,
  type IntegrityResult,
  type Scheme,
} from './sigblock';
import { parseCertificate, type CertInfo } from './x509';
import { findEntry, openZip, readEntry, type ZipArchive } from './zip';
import { buildFindings, type Finding } from './findings';

export type ArtifactKind = 'apk' | 'aab' | 'apk-set';
export type SchemeName = 'v1' | Scheme;

export interface SignerReport {
  scheme: SchemeName;
  cert: CertInfo;
  minSdk: number | null;
  maxSdk: number | null;
}

export interface LineageEntry {
  cert: CertInfo;
  flags: number;
}

export const PROOF_PATH = 'assets/adi-registration.properties';

export interface ProofFile {
  path: string;
  /** Raw text, exactly as stored. */
  text: string;
}

export interface ArtifactReport {
  fileName: string;
  size: number;
  kind: ArtifactKind;
  manifest: ManifestInfo;
  schemes: SchemeName[];
  signers: SignerReport[];
  /** The certificate current Android versions use for this app (newest v3.1/v3 signer, else v2, else v1). */
  currentCert: CertInfo | null;
  /** Rotation history, oldest first, when the APK carries a v3 proof-of-rotation lineage. */
  lineage: LineageEntry[];
  integrity: IntegrityResult[];
  /** Files named adi-registration.properties anywhere in the archive. */
  proofFiles: ProofFile[];
  /** Other signing-block entries worth surfacing (e.g. source stamp). */
  extras: string[];
  findings: Finding[];
  children: ArtifactReport[];
}

const EXTRA_NAMES: Record<number, string> = {
  [BLOCK_IDS.sourceStamp]: 'Source stamp (v2)',
  [BLOCK_IDS.sourceStampV1]: 'Source stamp (v1)',
  [BLOCK_IDS.dependencyInfo]: 'Dependency metadata (added by Android Gradle Plugin)',
  [BLOCK_IDS.playMetadata]: 'Google Play metadata',
};

const MAX_NESTED = 40;

function detectKind(zip: ZipArchive, fileName: string): ArtifactKind {
  if (findEntry(zip, 'AndroidManifest.xml')) return 'apk';
  if (findEntry(zip, 'base/manifest/AndroidManifest.xml')) return 'aab';
  if (zip.entries.some((e) => e.name.toLowerCase().endsWith('.apk'))) return 'apk-set';
  throw new ParseError(
    `${fileName} has no AndroidManifest.xml; expected an .apk, .aab, .apks or .xapk file`,
  );
}

async function v1Signers(zip: ZipArchive): Promise<CertInfo[]> {
  const blocks = zip.entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  const certs: CertInfo[] = [];
  for (const block of blocks) {
    for (const der of pkcs7SignerCerts(readEntry(zip, block))) {
      const info = await parseCertificate(der);
      if (!certs.some((c) => c.sha256 === info.sha256)) certs.push(info);
    }
  }
  return certs;
}

function pickCurrent(blockSigners: { s: BlockSigner; cert: CertInfo }[], v1: CertInfo[]): CertInfo | null {
  for (const scheme of ['v3.1', 'v3', 'v2'] as const) {
    const list = blockSigners.filter((x) => x.s.scheme === scheme);
    if (list.length) {
      list.sort((a, b) => (b.s.maxSdk ?? 0) - (a.s.maxSdk ?? 0));
      return list[0].cert;
    }
  }
  return v1[0] ?? null;
}

async function analyzeApkLike(fileName: string, bytes: Uint8Array, zip: ZipArchive, kind: 'apk' | 'aab'): Promise<ArtifactReport> {
  let manifest = emptyManifest();
  const manifestError: string[] = [];
  try {
    manifest =
      kind === 'apk'
        ? parseManifest(readEntry(zip, findEntry(zip, 'AndroidManifest.xml')!))
        : manifestFromElements(parseProtoXml(readEntry(zip, findEntry(zip, 'base/manifest/AndroidManifest.xml')!)));
  } catch (e) {
    manifestError.push((e as Error).message);
  }

  const signers: SignerReport[] = [];
  const schemes: SchemeName[] = [];
  const v1 = await v1Signers(zip);
  if (v1.length) schemes.push('v1');
  for (const cert of v1) signers.push({ scheme: 'v1', cert, minSdk: null, maxSdk: null });

  const integrity: IntegrityResult[] = [];
  const extras: string[] = [];
  const blockSigners: { s: BlockSigner; cert: CertInfo }[] = [];
  let lineage: LineageEntry[] = [];
  const block = kind === 'apk' ? findSigningBlock(zip) : null;
  if (block) {
    const digestCache = new Map<string, Uint8Array>();
    const ids: [number, Scheme][] = [
      [BLOCK_IDS.v2, 'v2'],
      [BLOCK_IDS.v3, 'v3'],
      [BLOCK_IDS.v31, 'v3.1'],
    ];
    for (const [id, scheme] of ids) {
      const pair = block.pairs.find((p) => p.id === id);
      if (!pair) continue;
      schemes.push(scheme);
      for (const s of parseSchemeBlock(scheme, pair.value)) {
        const cert = await parseCertificate(s.certs[0]);
        blockSigners.push({ s, cert });
        signers.push({ scheme, cert, minSdk: s.minSdk, maxSdk: s.maxSdk });
        integrity.push(await verifySigner(zip, block, s, digestCache));
        if (s.lineage && s.lineage.length > lineage.length) {
          lineage = [];
          for (const node of s.lineage) lineage.push({ cert: await parseCertificate(node.cert), flags: node.flags });
        }
      }
    }
    for (const p of block.pairs) if (EXTRA_NAMES[p.id]) extras.push(EXTRA_NAMES[p.id]);
  }

  const proofFiles: ProofFile[] = [];
  for (const e of zip.entries) {
    if (e.name.split('/').pop()?.toLowerCase() === 'adi-registration.properties') {
      const text = new TextDecoder().decode(readEntry(zip, e));
      proofFiles.push({ path: e.name, text });
    }
  }

  const report: ArtifactReport = {
    fileName,
    size: bytes.length,
    kind,
    manifest,
    schemes,
    signers,
    currentCert: pickCurrent(blockSigners, v1),
    lineage,
    integrity,
    proofFiles,
    extras,
    findings: [],
    children: [],
  };
  report.findings = buildFindings(report, manifestError);
  return report;
}

/** Analyses an .apk, .aab, or split-APK set (.apks / .xapk). Never throws for malformed input that is a ZIP. */
export async function analyzeArtifact(fileName: string, bytes: Uint8Array): Promise<ArtifactReport> {
  const zip = openZip(bytes);
  const kind = detectKind(zip, fileName);
  if (kind !== 'apk-set') return analyzeApkLike(fileName, bytes, zip, kind);

  const children: ArtifactReport[] = [];
  const inner = zip.entries.filter((e) => e.name.toLowerCase().endsWith('.apk')).slice(0, MAX_NESTED);
  for (const e of inner) {
    try {
      const data = readEntry(zip, e);
      const innerZip = openZip(data);
      children.push(await analyzeApkLike(`${fileName} › ${e.name}`, data, innerZip, 'apk'));
    } catch (err) {
      children.push(errorReport(`${fileName} › ${e.name}`, e.uncompressedSize, err as Error));
    }
  }
  // The base APK (no split attribute) represents the set.
  const base = children.find((c) => c.manifest.packageName && !c.manifest.split) ?? children[0];
  const report: ArtifactReport = {
    ...(base ?? errorReport(fileName, bytes.length, new ParseError('APK set contains no readable APKs'))),
    fileName,
    size: bytes.length,
    kind: 'apk-set',
    children,
  };
  report.findings = buildFindings(report, []);
  return report;
}

export function errorReport(fileName: string, size: number, err: Error): ArtifactReport {
  return {
    fileName,
    size,
    kind: 'apk',
    manifest: emptyManifest(),
    schemes: [],
    signers: [],
    currentCert: null,
    lineage: [],
    integrity: [],
    proofFiles: [],
    extras: [],
    findings: [{ id: 'parse-error', severity: 'error', title: 'Could not read this file', detail: err.message }],
    children: [],
  };
}

/** Safe wrapper used by the UI and CLI: turns any error into an error report. */
export async function analyzeSafely(fileName: string, bytes: Uint8Array): Promise<ArtifactReport> {
  try {
    return await analyzeArtifact(fileName, bytes);
  } catch (e) {
    return errorReport(fileName, bytes.length, e as Error);
  }
}
