import { ParseError, u16, u32 } from './bytes';

/** Subset of AndroidManifest.xml attributes that matter for registration. */
export interface ManifestInfo {
  packageName: string | null;
  versionCode: string | null;
  versionName: string | null;
  minSdk: number | null;
  targetSdk: number | null;
  debuggable: boolean;
  testOnly: boolean;
  split: string | null;
}

export const ATTR = {
  versionCode: 0x0101021b,
  versionName: 0x0101021c,
  minSdkVersion: 0x0101020c,
  targetSdkVersion: 0x01010270,
  debuggable: 0x0101000f,
  testOnly: 0x01010272,
} as const;

export interface XmlAttr {
  name: string;
  resId: number | null;
  /** Decoded value as a string ("true"/"false" for booleans, decimal for ints); null for references. */
  value: string | null;
}

export interface XmlElement {
  name: string;
  depth: number;
  attrs: XmlAttr[];
}

export function emptyManifest(): ManifestInfo {
  return {
    packageName: null,
    versionCode: null,
    versionName: null,
    minSdk: null,
    targetSdk: null,
    debuggable: false,
    testOnly: false,
    split: null,
  };
}

function readStringPool(b: Uint8Array, start: number): string[] {
  const headerSize = u16(b, start + 2);
  const count = u32(b, start + 8);
  const flags = u32(b, start + 16);
  const stringsStart = u32(b, start + 20);
  const utf8 = (flags & 0x100) !== 0;
  const out: string[] = [];
  const dec8 = new TextDecoder('utf-8');
  for (let i = 0; i < count; i++) {
    let p = start + stringsStart + u32(b, start + headerSize + i * 4);
    if (utf8) {
      // char length (skipped) then byte length, each 1 or 2 bytes.
      p += b[p] & 0x80 ? 2 : 1;
      let len = b[p];
      if (len & 0x80) {
        len = ((len & 0x7f) << 8) | b[p + 1];
        p += 2;
      } else p += 1;
      out.push(dec8.decode(b.subarray(p, p + len)));
    } else {
      let len = u16(b, p);
      if (len & 0x8000) {
        len = ((len & 0x7fff) << 16) | u16(b, p + 2);
        p += 4;
      } else p += 2;
      let s = '';
      for (let j = 0; j < len; j++) s += String.fromCharCode(u16(b, p + j * 2));
      out.push(s);
    }
  }
  return out;
}

/** Walks a compiled (binary) Android XML document and returns its start elements. */
export function parseBinaryXml(b: Uint8Array): XmlElement[] {
  if (b.length < 8 || u16(b, 0) !== 0x0003) throw new ParseError('AndroidManifest.xml is not compiled binary XML');
  let strings: string[] = [];
  let resMap: number[] = [];
  const elements: XmlElement[] = [];
  let depth = 0;
  let p = u16(b, 2);
  const end = Math.min(b.length, u32(b, 4));
  while (p + 8 <= end) {
    const type = u16(b, p);
    const headerSize = u16(b, p + 2);
    const size = u32(b, p + 4);
    if (size < 8 || p + size > end) throw new ParseError('Corrupt chunk in binary XML');
    if (type === 0x0001) strings = readStringPool(b, p);
    else if (type === 0x0180) {
      resMap = [];
      for (let q = p + headerSize; q + 4 <= p + size; q += 4) resMap.push(u32(b, q));
    } else if (type === 0x0102) {
      const ext = p + headerSize;
      const nameIdx = u32(b, ext + 4);
      const attrStart = u16(b, ext + 8);
      const attrSize = u16(b, ext + 10);
      const attrCount = u16(b, ext + 12);
      const attrs: XmlAttr[] = [];
      for (let i = 0; i < attrCount; i++) {
        const a = ext + attrStart + i * attrSize;
        const nameI = u32(b, a + 4);
        const rawI = u32(b, a + 8);
        const dataType = b[a + 15];
        const data = u32(b, a + 16);
        let value: string | null = null;
        if (dataType === 0x03) value = strings[data] ?? null;
        else if (dataType === 0x10) value = String(data | 0);
        else if (dataType === 0x11) value = String(data);
        else if (dataType === 0x12) value = data !== 0 ? 'true' : 'false';
        else if (rawI !== 0xffffffff) value = strings[rawI] ?? null;
        attrs.push({ name: strings[nameI] ?? '', resId: nameI < resMap.length ? resMap[nameI] : null, value });
      }
      elements.push({ name: strings[nameIdx] ?? '', depth, attrs });
      depth++;
    } else if (type === 0x0103) depth--;
    p += size;
  }
  return elements;
}

function attr(el: XmlElement | undefined, name: string, resId?: number): string | null {
  if (!el) return null;
  const hit = (resId !== undefined && el.attrs.find((a) => a.resId === resId)) || el.attrs.find((a) => a.name === name);
  return hit ? hit.value : null;
}

function int(v: string | null): number | null {
  if (v === null || !/^-?\d+$/.test(v)) return null;
  return Number(v);
}

/** Builds ManifestInfo from start elements produced by either the binary or the proto XML reader. */
export function manifestFromElements(elements: XmlElement[]): ManifestInfo {
  const m = emptyManifest();
  const root = elements.find((e) => e.depth === 0 && e.name === 'manifest');
  if (!root) throw new ParseError('No <manifest> root element');
  const usesSdk = elements.find((e) => e.depth === 1 && e.name === 'uses-sdk');
  const app = elements.find((e) => e.depth === 1 && e.name === 'application');
  m.packageName = attr(root, 'package');
  m.versionCode = attr(root, 'versionCode', ATTR.versionCode);
  m.versionName = attr(root, 'versionName', ATTR.versionName);
  m.split = attr(root, 'split');
  m.minSdk = int(attr(usesSdk, 'minSdkVersion', ATTR.minSdkVersion));
  m.targetSdk = int(attr(usesSdk, 'targetSdkVersion', ATTR.targetSdkVersion));
  m.debuggable = attr(app, 'debuggable', ATTR.debuggable) === 'true';
  m.testOnly = attr(app, 'testOnly', ATTR.testOnly) === 'true';
  return m;
}

export function parseManifest(b: Uint8Array): ManifestInfo {
  return manifestFromElements(parseBinaryXml(b));
}
