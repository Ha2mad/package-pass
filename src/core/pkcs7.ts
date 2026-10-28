import { children, intBytes, parseDer, raw } from './asn1';
import { ParseError, toHex } from './bytes';
import { certSerial } from './x509';

/**
 * Extracts the signer certificate(s) from a JAR (APK v1 / AAB) signature block
 * (META-INF/*.RSA|*.DSA|*.EC), which is a CMS/PKCS#7 SignedData structure.
 * Returns the DER of the certificate each SignerInfo points to (by issuer + serial).
 */
export function pkcs7SignerCerts(der: Uint8Array): Uint8Array[] {
  const contentInfo = parseDer(der);
  const [, explicit] = children(contentInfo);
  if (!explicit) throw new ParseError('PKCS#7 block has no content');
  const signedData = children(explicit)[0];
  const parts = children(signedData);
  const certs: Uint8Array[] = [];
  let signerInfos: ReturnType<typeof children> = [];
  for (const p of parts) {
    if (p.cls === 2 && p.tag === 0) for (const c of children(p)) certs.push(raw(c));
    else if (p.cls === 0 && p.tag === 0x11) signerInfos = children(p); // last SET is signerInfos
  }
  if (certs.length === 0) throw new ParseError('PKCS#7 block contains no certificates');
  const result: Uint8Array[] = [];
  for (const si of signerInfos) {
    const sid = children(si)[1];
    if (!sid) continue;
    const serialNode = children(sid)[1];
    if (!serialNode) continue;
    const serial = toHex(intBytes(serialNode));
    const match = certs.find((c) => certSerial(c) === serial);
    if (match && !result.includes(match)) result.push(match);
  }
  return result.length > 0 ? result : [certs[0]];
}
