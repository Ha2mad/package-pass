import { analyzeSafely, type ArtifactReport } from '../core';

export const ACCEPT = '.apk,.aab,.apks,.xapk';

export async function readFiles(files: Iterable<File>): Promise<ArtifactReport[]> {
  const out: ArtifactReport[] = [];
  for (const f of files) out.push(await analyzeSafely(f.name, new Uint8Array(await f.arrayBuffer())));
  return out;
}

export const SAMPLES = ['alpha-direct.apk', 'alpha-repo.apk', 'alpha.aab', 'beta-rotated.apk', 'gamma-ec.apk', 'debug-signed.apk'];

export async function loadSamples(names = SAMPLES): Promise<ArtifactReport[]> {
  const out: ArtifactReport[] = [];
  for (const n of names) {
    const res = await fetch(`./samples/${n}`);
    out.push(await analyzeSafely(n, new Uint8Array(await res.arrayBuffer())));
  }
  return out;
}

export function download(name: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
