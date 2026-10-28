import { children, intBytes, oid, parseDer, raw } from './asn1';
import { ascii, bytesEqual, copy, Cursor, ParseError, u32, u64 } from './bytes';
import { certSpki } from './x509';
import type { ZipArchive } from './zip';

export const BLOCK_IDS = {
  v2: 0x7109871a,
  v3: 0xf05368c0,
  v31: 0x1b93ad61,
  sourceStamp: 0x6dff800d,
  sourceStampV1: 0x2b09189e,
  verityPadding: 0x42726577,
  dependencyInfo: 0x504b4453,
  playMetadata: 0x71777777,
} as const;

const PROOF_OF_ROTATION_ATTR = 0x3ba06f8c;

export type Scheme = 'v2' | 'v3' | 'v3.1';

export interface LineageNode {
  cert: Uint8Array;
  flags: number;
}

export interface BlockSigner {
  scheme: Scheme;
  certs: Uint8Array[];
  publicKey: Uint8Array;
  signedData: Uint8Array;
  digests: { alg: number; digest: Uint8Array }[];
  signatures: { alg: number; sig: Uint8Array }[];
  minSdk: number | null;
  maxSdk: number | null;
  lineage: LineageNode[] | null;
}

export interface SigningBlock {
  start: number;
  pairs: { id: number; value: Uint8Array }[];
}

/** Locates the APK Signing Block that sits directly before the ZIP central directory. */
export function findSigningBlock(zip: ZipArchive): SigningBlock | null {
  const b = zip.bytes;
  const cd = zip.cdOffset;
  if (cd < 32) return null;
  if (ascii(b.subarray(cd - 16, cd)) !== 'APK Sig Block 42') return null;
  const sizeInFooter = u64(b, cd - 24);
  const start = cd - sizeInFooter - 8;
  if (start < 0 || u64(b, start) !== sizeInFooter) throw new ParseError('APK Signing Block sizes do not match');
  const pairs: { id: number; value: Uint8Array }[] = [];
  let p = start + 8;
  const end = cd - 24;
  while (p < end) {
    const len = u64(b, p);
    if (len < 4 || p + 8 + len > end) throw new ParseError('Corrupt APK Signing Block pair');
    pairs.push({ id: u32(b, p + 8), value: b.subarray(p + 12, p + 8 + len) });
    p += 8 + len;
  }
  return { start, pairs };
}

function parseLineage(value: Uint8Array): LineageNode[] {
  const c = new Cursor(value);
  c.u32(); // version
  const nodes: LineageNode[] = [];
  while (c.remaining > 0) {
    const node = new Cursor(c.lengthPrefixed());
    const signed = new Cursor(node.lengthPrefixed());
    const cert = signed.lengthPrefixed();
    const flags = node.u32();
    nodes.push({ cert, flags });
  }
  return nodes;
}

export function parseSchemeBlock(scheme: Scheme, value: Uint8Array): BlockSigner[] {
  const signers = new Cursor(value).sequence();
  return signers.map((s) => {
    const c = new Cursor(s);
    const signedData = c.lengthPrefixed();
    let minSdk: number | null = null;
    let maxSdk: number | null = null;
    if (scheme !== 'v2') {
      minSdk = c.u32();
      maxSdk = c.u32();
    }
    const signatures = c.sequence().map((x) => {
      const sc = new Cursor(x);
      return { alg: sc.u32(), sig: sc.lengthPrefixed() };
    });
    const publicKey = c.lengthPrefixed();

    const sd = new Cursor(signedData);
    const digests = sd.sequence().map((x) => {
      const dc = new Cursor(x);
      return { alg: dc.u32(), digest: dc.lengthPrefixed() };
    });
    const certs = sd.sequence();
    if (scheme !== 'v2') {
      sd.u32();
      sd.u32();
    }
    let lineage: LineageNode[] | null = null;
    if (sd.remaining >= 4) {
      for (const attr of sd.sequence()) {
        const ac = new Cursor(attr);
        const id = ac.u32();
        if (id === PROOF_OF_ROTATION_ATTR && scheme !== 'v2') lineage = parseLineage(attr.subarray(4));
      }
    }
    return { scheme, certs, publicKey, signedData, digests, signatures, minSdk, maxSdk, lineage };
  });
}

// ---------------------------------------------------------------------------
// Integrity verification (APK Signature Scheme v2/v3 content digests + signatures)

interface AlgSpec {
  digest: 'SHA-256' | 'SHA-512';
  kind: 'RSA-PSS' | 'RSA-PKCS1' | 'ECDSA' | 'DSA';
  verity?: boolean;
}

export const SIG_ALGS: Record<number, AlgSpec> = {
  0x0101: { digest: 'SHA-256', kind: 'RSA-PSS' },
  0x0102: { digest: 'SHA-512', kind: 'RSA-PSS' },
  0x0103: { digest: 'SHA-256', kind: 'RSA-PKCS1' },
  0x0104: { digest: 'SHA-512', kind: 'RSA-PKCS1' },
  0x0201: { digest: 'SHA-256', kind: 'ECDSA' },
  0x0202: { digest: 'SHA-512', kind: 'ECDSA' },
  0x0301: { digest: 'SHA-256', kind: 'DSA' },
  0x0421: { digest: 'SHA-256', kind: 'RSA-PKCS1', verity: true },
  0x0423: { digest: 'SHA-256', kind: 'ECDSA', verity: true },
  0x0425: { digest: 'SHA-256', kind: 'DSA', verity: true },
};

const CHUNK = 1024 * 1024;

/** Computes the chunked content digest defined by APK Signature Scheme v2. */
export async function contentDigest(zip: ZipArchive, block: SigningBlock, alg: 'SHA-256' | 'SHA-512'): Promise<Uint8Array> {
  const b = zip.bytes;
  const eocd = b.slice(zip.eocdOffset);
  // The EOCD's central-directory offset is treated as pointing at the signing block.
  const so = block.start;
  eocd[16] = so & 0xff;
  eocd[17] = (so >>> 8) & 0xff;
  eocd[18] = (so >>> 16) & 0xff;
  eocd[19] = (so >>> 24) & 0xff;
  const sections = [b.subarray(0, block.start), b.subarray(zip.cdOffset, zip.eocdOffset), eocd];
  const chunkDigests: Uint8Array[] = [];
  for (const sec of sections) {
    for (let off = 0; off < sec.length; off += CHUNK) {
      const chunk = sec.subarray(off, Math.min(sec.length, off + CHUNK));
      const input = new Uint8Array(5 + chunk.length);
      input[0] = 0xa5;
      new DataView(input.buffer).setUint32(1, chunk.length, true);
      input.set(chunk, 5);
      chunkDigests.push(new Uint8Array(await crypto.subtle.digest(alg, input)));
    }
  }
  const dlen = chunkDigests[0]?.length ?? (alg === 'SHA-256' ? 32 : 64);
  const top = new Uint8Array(5 + chunkDigests.length * dlen);
  top[0] = 0x5a;
  new DataView(top.buffer).setUint32(1, chunkDigests.length, true);
  chunkDigests.forEach((d, i) => top.set(d, 5 + i * dlen));
  return new Uint8Array(await crypto.subtle.digest(alg, top));
}

/** Converts a DER ECDSA signature to the raw r||s form WebCrypto expects. */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
  const seq = parseDer(der);
  const [r, s] = children(seq);
  const out = new Uint8Array(size * 2);
  const rb = intBytes(r).slice(-size);
  const sb = intBytes(s).slice(-size);
  out.set(rb, size - rb.length);
  out.set(sb, size * 2 - sb.length);
  return out;
}

const CURVE_BY_OID: Record<string, { name: string; size: number }> = {
  '1.2.840.10045.3.1.7': { name: 'P-256', size: 32 },
  '1.3.132.0.34': { name: 'P-384', size: 48 },
  '1.3.132.0.35': { name: 'P-521', size: 66 },
};

async function verifySignature(spec: AlgSpec, spki: Uint8Array, data: Uint8Array, sig: Uint8Array): Promise<boolean | null> {
  const hash = spec.digest;
  try {
    if (spec.kind === 'RSA-PKCS1') {
      const key = await crypto.subtle.importKey('spki', copy(spki), { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
      return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, copy(sig), copy(data));
    }
    if (spec.kind === 'RSA-PSS') {
      const key = await crypto.subtle.importKey('spki', copy(spki), { name: 'RSA-PSS', hash }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: hash === 'SHA-256' ? 32 : 64 }, key, copy(sig), copy(data));
    }
    if (spec.kind === 'ECDSA') {
      const params = children(children(parseDer(spki))[0])[1];
      const curve = params ? CURVE_BY_OID[oid(params)] : undefined;
      if (!curve) return null;
      const key = await crypto.subtle.importKey('spki', copy(spki), { name: 'ECDSA', namedCurve: curve.name }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'ECDSA', hash }, key, copy(ecdsaDerToRaw(sig, curve.size)), copy(data));
    }
  } catch {
    return false;
  }
  return null; // DSA is not available in WebCrypto
}

export type IntegrityStatus = 'verified' | 'failed' | 'unchecked';

export interface IntegrityResult {
  scheme: Scheme;
  status: IntegrityStatus;
  detail: string;
}

/**
 * Verifies one v2/v3 signer: the public key must match the first certificate, at least one
 * supported signature over signed-data must verify, and the content digest must match the file.
 */
export async function verifySigner(
  zip: ZipArchive,
  block: SigningBlock,
  signer: BlockSigner,
  digestCache: Map<string, Uint8Array>,
): Promise<IntegrityResult> {
  const scheme = signer.scheme;
  if (signer.certs.length === 0) return { scheme, status: 'failed', detail: 'Signer has no certificate' };
  if (!bytesEqual(raw(certSpki(signer.certs[0])), signer.publicKey)) {
    return { scheme, status: 'failed', detail: 'Public key does not match the signer certificate' };
  }
  const sigAlgs = signer.signatures.map((s) => s.alg).sort();
  const digAlgs = signer.digests.map((d) => d.alg).sort();
  if (sigAlgs.join() !== digAlgs.join()) {
    return { scheme, status: 'failed', detail: 'Signature and digest algorithm lists differ' };
  }
  let checked = 0;
  for (const s of signer.signatures) {
    const spec = SIG_ALGS[s.alg];
    if (!spec || spec.verity) continue;
    const ok = await verifySignature(spec, signer.publicKey, signer.signedData, s.sig);
    if (ok === null) continue;
    if (!ok) return { scheme, status: 'failed', detail: `Signature (algorithm 0x${s.alg.toString(16)}) does not verify` };
    const recorded = signer.digests.find((d) => d.alg === s.alg)!.digest;
    let actual = digestCache.get(spec.digest);
    if (!actual) {
      actual = await contentDigest(zip, block, spec.digest);
      digestCache.set(spec.digest, actual);
    }
    if (!bytesEqual(actual, recorded)) {
      return { scheme, status: 'failed', detail: 'APK contents do not match the signed digest (file modified after signing?)' };
    }
    checked++;
  }
  if (checked === 0) {
    return { scheme, status: 'unchecked', detail: 'Only DSA or verity signature algorithms present; not verifiable in the browser' };
  }
  return { scheme, status: 'verified', detail: 'Signature and whole-file digest verified' };
}

