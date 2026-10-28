/** Small helpers for reading little-endian binary structures from a Uint8Array. */

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

export function u16(b: Uint8Array, off: number): number {
  if (off + 2 > b.length) throw new ParseError(`Unexpected end of data reading u16 at ${off}`);
  return b[off] | (b[off + 1] << 8);
}

export function u32(b: Uint8Array, off: number): number {
  if (off + 4 > b.length) throw new ParseError(`Unexpected end of data reading u32 at ${off}`);
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16)) + b[off + 3] * 0x1000000;
}

/** Reads a u64 as a JS number; throws if it does not fit in 2^53. */
export function u64(b: Uint8Array, off: number): number {
  const lo = u32(b, off);
  const hi = u32(b, off + 4);
  if (hi > 0x1fffff) throw new ParseError(`64-bit value at ${off} is too large`);
  return hi * 0x100000000 + lo;
}

/** Sequential reader over a slice, for the length-prefixed APK Signature Scheme structures. */
export class Cursor {
  pos = 0;
  constructor(readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.pos;
  }

  u32(): number {
    const v = u32(this.buf, this.pos);
    this.pos += 4;
    return v;
  }

  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.length) {
      throw new ParseError(`Length ${n} at offset ${this.pos} exceeds the enclosing structure`);
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** u32 length followed by that many bytes. */
  lengthPrefixed(): Uint8Array {
    return this.bytes(this.u32());
  }

  /** Reads a u32-length-prefixed sequence of u32-length-prefixed items. */
  sequence(): Uint8Array[] {
    const seq = new Cursor(this.lengthPrefixed());
    const items: Uint8Array[] = [];
    while (seq.remaining > 0) items.push(seq.lengthPrefixed());
    return items;
  }
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s.toUpperCase();
}

export function colonHex(hex: string): string {
  return hex.toUpperCase().match(/.{2}/g)?.join(':') ?? '';
}

/** Normalises user-entered fingerprints ("AB:CD..", "ab cd..", "abcd..") to 64 upper-case hex chars, or null. */
export function normalizeFingerprint(input: string): string | null {
  const hex = input.replace(/[\s:-]/g, '').toUpperCase();
  return /^[0-9A-F]{64}$/.test(hex) ? hex : null;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function ascii(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return s;
}

/** Copies into a fresh ArrayBuffer-backed array (WebCrypto rejects views over SharedArrayBuffer and is fussy about offsets). */
export function copy(b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(b.length));
  out.set(b);
  return out;
}
