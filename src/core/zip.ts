import { inflateSync } from 'fflate';
import { ParseError, u16, u32 } from './bytes';

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

export interface ZipArchive {
  bytes: Uint8Array;
  entries: ZipEntry[];
  /** Offset of the first central directory record. */
  cdOffset: number;
  cdSize: number;
  eocdOffset: number;
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const MAX_ENTRY_BYTES = 256 * 1024 * 1024;

export function findEocd(bytes: Uint8Array): number {
  const min = Math.max(0, bytes.length - 22 - 0xffff);
  for (let i = bytes.length - 22; i >= min; i--) {
    if (u32(bytes, i) === EOCD_SIG && i + 22 + u16(bytes, i + 20) === bytes.length) return i;
  }
  throw new ParseError('Not a ZIP archive (no end-of-central-directory record found)');
}

export function openZip(bytes: Uint8Array): ZipArchive {
  if (bytes.length < 22) throw new ParseError('File is too small to be a ZIP archive');
  const eocdOffset = findEocd(bytes);
  const count = u16(bytes, eocdOffset + 10);
  const cdSize = u32(bytes, eocdOffset + 12);
  const cdOffset = u32(bytes, eocdOffset + 16);
  if (cdOffset === 0xffffffff || count === 0xffff) {
    throw new ParseError('ZIP64 archives are not supported');
  }
  if (cdOffset + cdSize > eocdOffset) throw new ParseError('Central directory overlaps the end record');
  const decoder = new TextDecoder();
  const entries: ZipEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (u32(bytes, p) !== CD_SIG) throw new ParseError(`Bad central directory record #${i}`);
    const method = u16(bytes, p + 10);
    const compressedSize = u32(bytes, p + 20);
    const uncompressedSize = u32(bytes, p + 24);
    const nameLen = u16(bytes, p + 28);
    const extraLen = u16(bytes, p + 30);
    const commentLen = u16(bytes, p + 32);
    const localHeaderOffset = u32(bytes, p + 42);
    const name = decoder.decode(bytes.subarray(p + 46, p + 46 + nameLen));
    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { bytes, entries, cdOffset, cdSize, eocdOffset };
}

export function findEntry(zip: ZipArchive, name: string): ZipEntry | undefined {
  return zip.entries.find((e) => e.name === name);
}

export function readEntry(zip: ZipArchive, entry: ZipEntry): Uint8Array {
  const b = zip.bytes;
  const p = entry.localHeaderOffset;
  if (u32(b, p) !== LOCAL_SIG) throw new ParseError(`Bad local header for ${entry.name}`);
  const start = p + 30 + u16(b, p + 26) + u16(b, p + 28);
  const end = start + entry.compressedSize;
  if (end > b.length) throw new ParseError(`Entry ${entry.name} runs past the end of the file`);
  if (entry.uncompressedSize > MAX_ENTRY_BYTES) throw new ParseError(`Entry ${entry.name} is too large to inspect`);
  const raw = b.subarray(start, end);
  if (entry.method === 0) return raw;
  if (entry.method === 8) return inflateSync(raw, { out: new Uint8Array(entry.uncompressedSize) });
  throw new ParseError(`Entry ${entry.name} uses unsupported compression method ${entry.method}`);
}
