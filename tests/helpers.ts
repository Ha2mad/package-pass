import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { analyzeArtifact } from '../src/core';

export const fixture = (name: string): Uint8Array =>
  new Uint8Array(readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))));

export const expected: Record<string, string> = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/expected-fingerprints.json', import.meta.url)), 'utf8'),
);

export const analyze = (name: string) => analyzeArtifact(name, fixture(name));
