import { ParseError } from './bytes';

/** A minimal DER node. `start` is the offset of the tag byte, `end` is one past the last content byte. */
export interface Asn1 {
  cls: number; // 0 universal, 1 application, 2 context, 3 private
  constructed: boolean;
  tag: number;
  start: number;
  contentStart: number;
  end: number;
  buf: Uint8Array;
}

export function parseDer(buf: Uint8Array, offset = 0, limit = buf.length): Asn1 {
  if (offset + 2 > limit) throw new ParseError('Truncated ASN.1 header');
  const id = buf[offset];
  const cls = id >> 6;
  const constructed = (id & 0x20) !== 0;
  let tag = id & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    let b: number;
    do {
      if (p >= limit) throw new ParseError('Truncated ASN.1 tag');
      b = buf[p++];
      tag = tag * 128 + (b & 0x7f);
    } while (b & 0x80);
  }
  if (p >= limit) throw new ParseError('Truncated ASN.1 length');
  let len = buf[p++];
  if (len === 0x80) throw new ParseError('Indefinite-length (BER) encoding is not supported');
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new ParseError('ASN.1 length too large');
    len = 0;
    for (let i = 0; i < n; i++) {
      if (p >= limit) throw new ParseError('Truncated ASN.1 length');
      len = len * 256 + buf[p++];
    }
  }
  const end = p + len;
  if (end > limit) throw new ParseError('ASN.1 element runs past its container');
  return { cls, constructed, tag, start: offset, contentStart: p, end, buf };
}

export function children(node: Asn1): Asn1[] {
  const out: Asn1[] = [];
  let p = node.contentStart;
  while (p < node.end) {
    const child = parseDer(node.buf, p, node.end);
    out.push(child);
    p = child.end;
  }
  return out;
}

export function content(node: Asn1): Uint8Array {
  return node.buf.subarray(node.contentStart, node.end);
}

export function raw(node: Asn1): Uint8Array {
  return node.buf.subarray(node.start, node.end);
}

export function isSeq(n: Asn1): boolean {
  return n.cls === 0 && n.tag === 0x10;
}

export function oid(node: Asn1): string {
  const b = content(node);
  if (b.length === 0) return '';
  const parts: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  if (b[0] >= 80) {
    parts[0] = 2;
    parts[1] = b[0] - 80;
  }
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

export function str(node: Asn1): string {
  const b = content(node);
  if (node.tag === 0x1e) {
    // BMPString (UTF-16BE)
    let s = '';
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
    return s;
  }
  return new TextDecoder().decode(b);
}

/** Unsigned big-endian integer contents with leading zero bytes removed. */
export function intBytes(node: Asn1): Uint8Array {
  let b = content(node);
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return b;
}

export function time(node: Asn1): string | null {
  const s = str(node);
  let m: RegExpMatchArray | null;
  if (node.tag === 0x17 && (m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/))) {
    const yy = Number(m[1]);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}Z`;
  }
  if (node.tag === 0x18 && (m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/))) {
    return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}Z`;
  }
  return null;
}
