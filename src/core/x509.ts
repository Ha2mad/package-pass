import { children, content, intBytes, isSeq, oid, parseDer, raw, str, time, type Asn1 } from './asn1';
import { ParseError, toHex, copy } from './bytes';

export interface PublicKeyInfo {
  algorithm: 'RSA' | 'EC' | 'DSA' | 'Ed25519' | 'unknown';
  bits?: number;
  curve?: string;
}

export interface CertInfo {
  sha256: string; // 64 upper-case hex chars, no separators
  sha1: string;
  subject: string;
  subjectCN: string | null;
  issuer: string;
  serial: string;
  notBefore: string | null;
  notAfter: string | null;
  signatureAlgorithm: string;
  publicKey: PublicKeyInfo;
  selfSigned: boolean;
  /** Matches the well-known Android SDK debug certificate subject. */
  isDebug: boolean;
}

const NAME_OIDS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'SERIALNUMBER',
  '1.2.840.113549.1.9.1': 'E',
};

const SIG_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.4': 'MD5withRSA',
  '1.2.840.113549.1.1.5': 'SHA1withRSA',
  '1.2.840.113549.1.1.11': 'SHA256withRSA',
  '1.2.840.113549.1.1.12': 'SHA384withRSA',
  '1.2.840.113549.1.1.13': 'SHA512withRSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'SHA1withECDSA',
  '1.2.840.10045.4.3.2': 'SHA256withECDSA',
  '1.2.840.10045.4.3.3': 'SHA384withECDSA',
  '1.2.840.10045.4.3.4': 'SHA512withECDSA',
  '1.2.840.10040.4.3': 'SHA1withDSA',
  '2.16.840.1.101.3.4.3.2': 'SHA256withDSA',
  '1.3.101.112': 'Ed25519',
};

const CURVES: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
};

function formatName(node: Asn1): { text: string; cn: string | null } {
  const parts: string[] = [];
  let cn: string | null = null;
  for (const rdn of children(node)) {
    for (const atv of children(rdn)) {
      const [type, value] = children(atv);
      if (!type || !value) continue;
      const o = oid(type);
      const key = NAME_OIDS[o] ?? o;
      const v = str(value);
      if (key === 'CN' && cn === null) cn = v;
      parts.push(`${key}=${v}`);
    }
  }
  return { text: parts.reverse().join(', '), cn };
}

export function parsePublicKey(spki: Asn1): PublicKeyInfo {
  const [alg, bitString] = children(spki);
  const [algOid, params] = children(alg);
  const o = oid(algOid);
  if (o === '1.2.840.113549.1.1.1') {
    // BIT STRING: first content byte is the unused-bits count.
    const keyDer = content(bitString).subarray(1);
    const rsa = parseDer(keyDer);
    const [modulus] = children(rsa);
    const m = intBytes(modulus);
    let bits = m.length * 8;
    for (let top = m[0]; top < 0x80 && bits > 0; top <<= 1) bits--;
    return { algorithm: 'RSA', bits };
  }
  if (o === '1.2.840.10045.2.1') {
    const curveOid = params ? oid(params) : '';
    const curve = CURVES[curveOid] ?? curveOid;
    const bits = curve === 'P-256' ? 256 : curve === 'P-384' ? 384 : curve === 'P-521' ? 521 : undefined;
    return { algorithm: 'EC', curve, bits };
  }
  if (o === '1.2.840.10040.4.1') {
    let bits: number | undefined;
    if (params && isSeq(params)) {
      const [p] = children(params);
      if (p) bits = intBytes(p).length * 8;
    }
    return { algorithm: 'DSA', bits };
  }
  if (o === '1.3.101.112') return { algorithm: 'Ed25519', bits: 256 };
  return { algorithm: 'unknown' };
}

async function digest(alg: 'SHA-256' | 'SHA-1', data: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest(alg, copy(data))));
}

/** Locates the SubjectPublicKeyInfo of a DER certificate. */
export function certSpki(der: Uint8Array): Asn1 {
  const cert = parseDer(der);
  const tbs = children(children(cert)[0]);
  const off = tbs[0].cls === 2 && tbs[0].tag === 0 ? 1 : 0;
  return tbs[off + 5];
}

export function certSerial(der: Uint8Array): string {
  const tbs = children(children(parseDer(der))[0]);
  const off = tbs[0].cls === 2 && tbs[0].tag === 0 ? 1 : 0;
  return toHex(intBytes(tbs[off]));
}

export async function parseCertificate(der: Uint8Array): Promise<CertInfo> {
  let cert: Asn1;
  try {
    cert = parseDer(der);
  } catch (e) {
    throw new ParseError(`Unreadable certificate: ${(e as Error).message}`);
  }
  const [tbsNode, sigAlgNode] = children(cert);
  if (!tbsNode || !isSeq(tbsNode)) throw new ParseError('Certificate is not an X.509 SEQUENCE');
  const tbs = children(tbsNode);
  const off = tbs[0].cls === 2 && tbs[0].tag === 0 ? 1 : 0;
  const serial = toHex(intBytes(tbs[off]));
  const issuer = formatName(tbs[off + 2]);
  const [nb, na] = children(tbs[off + 3]);
  const subject = formatName(tbs[off + 4]);
  const publicKey = parsePublicKey(tbs[off + 5]);
  const sigOid = oid(children(sigAlgNode)[0]);
  const isDebug = /^CN=Android Debug(,|$)/.test(subject.text) || subject.cn === 'Android Debug';
  return {
    sha256: await digest('SHA-256', raw(cert)),
    sha1: await digest('SHA-1', raw(cert)),
    subject: subject.text,
    subjectCN: subject.cn,
    issuer: issuer.text,
    serial,
    notBefore: time(nb),
    notAfter: time(na),
    signatureAlgorithm: SIG_OIDS[sigOid] ?? sigOid,
    publicKey,
    selfSigned: issuer.text === subject.text,
    isDebug,
  };
}
