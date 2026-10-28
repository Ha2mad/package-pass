import { ParseError } from './bytes';
import type { XmlAttr, XmlElement } from './axml';

/**
 * Reads the aapt2 protobuf XML (aapt.pb.XmlNode) used for AndroidManifest.xml inside
 * Android App Bundles. Only the fields needed for element names and attribute values are decoded.
 */
interface Field {
  no: number;
  wire: number;
  varint?: number;
  bytes?: Uint8Array;
}

function fields(b: Uint8Array): Field[] {
  const out: Field[] = [];
  let p = 0;
  const varint = (): number => {
    let v = 0;
    let mul = 1;
    for (;;) {
      if (p >= b.length) throw new ParseError('Truncated protobuf varint');
      const x = b[p++];
      v += (x & 0x7f) * mul;
      if (!(x & 0x80)) return v;
      mul *= 128;
      if (mul > 2 ** 63) throw new ParseError('Protobuf varint too long');
    }
  };
  while (p < b.length) {
    const key = varint();
    const no = Math.floor(key / 8);
    const wire = key & 7;
    if (wire === 0) out.push({ no, wire, varint: varint() });
    else if (wire === 2) {
      const len = varint();
      if (p + len > b.length) throw new ParseError('Truncated protobuf field');
      out.push({ no, wire, bytes: b.subarray(p, p + len) });
      p += len;
    } else if (wire === 1) p += 8;
    else if (wire === 5) {
      if (p + 4 > b.length) throw new ParseError('Truncated protobuf fixed32');
      out.push({ no, wire, varint: b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24) });
      p += 4;
    } else throw new ParseError(`Unsupported protobuf wire type ${wire}`);
  }
  return out;
}

const dec = new TextDecoder();

function walk(node: Uint8Array, depth: number, out: XmlElement[]): void {
  const element = fields(node).find((f) => f.no === 1 && f.bytes)?.bytes;
  if (!element) return;
  const ef = fields(element);
  const name = dec.decode(ef.find((f) => f.no === 3)?.bytes ?? new Uint8Array());
  const attrs: XmlAttr[] = [];
  for (const f of ef) {
    if (f.no !== 4 || !f.bytes) continue;
    const af = fields(f.bytes);
    const aName = dec.decode(af.find((x) => x.no === 2)?.bytes ?? new Uint8Array());
    const valueBytes = af.find((x) => x.no === 3)?.bytes;
    const resId = af.find((x) => x.no === 5)?.varint ?? null;
    attrs.push({ name: aName, resId, value: valueBytes ? dec.decode(valueBytes) : null });
  }
  out.push({ name, depth, attrs });
  for (const f of ef) if (f.no === 5 && f.bytes) walk(f.bytes, depth + 1, out);
}

export function parseProtoXml(b: Uint8Array): XmlElement[] {
  const out: XmlElement[] = [];
  walk(b, 0, out);
  if (out.length === 0) throw new ParseError('Bundle manifest is not a protobuf XmlNode');
  return out;
}
