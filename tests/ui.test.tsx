// @vitest-environment jsdom
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import { App } from '../src/ui/App';

const tick = () => new Promise<void>((r) => setTimeout(r, 30));
async function until(fn: () => boolean) {
  for (let i = 0; i < 200 && !fn(); i++) await act(tick);
}

describe('App', () => {
  let root: HTMLElement;
  beforeEach(() => {
    document.body.innerHTML = '<div id="r"></div>';
    root = document.getElementById('r')!;
    vi.stubGlobal('fetch', async (url: string) => {
      const buf = readFileSync(join(__dirname, '..', 'public', 'samples', url.split('/').pop()!));
      return { ok: true, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) };
    });
  });
  const button = (text: string) => Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim().startsWith(text))!;

  it('loads samples and builds the registration plan', async () => {
    await act(() => { render(<App />, root); });
    expect(root.textContent).toContain('Package Pass');
    await act(async () => { button('Load sample files').click(); });
    await until(() => root.textContent!.includes('com.axenova.beta'));
    const text = root.textContent!;
    expect(text).toContain('com.axenova.alpha');
    expect(text).toContain('com.axenova.gamma');
    // release key fingerprint (from tests/fixtures/expected-fingerprints.json) appears in the plan
    const expected = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'expected-fingerprints.json'), 'utf8'));
    expect(text.replace(/:/g, '').toUpperCase()).toContain(String(expected.release).replace(/:/g, '').toUpperCase());
    expect(text.toLowerCase()).toContain('debug');
  });

  it('runs a passing proof-APK preflight on the sample', async () => {
    await act(() => { render(<App />, root); });
    await act(async () => { button('Proof APK check').click(); });
    await act(async () => { button('Try the sample proof APK').click(); });
    await until(() => !!root.querySelector('.verdict'));
    const expected = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'expected-fingerprints.json'), 'utf8'));
    const fpInput = root.querySelectorAll('form.inputs input')[1] as HTMLInputElement;
    await act(async () => { fpInput.value = expected.release; fpInput.dispatchEvent(new Event('input', { bubbles: true })); });
    await act(tick);
    expect(root.querySelector('.verdict')!.className).toContain('ready');
    expect(root.querySelector('.verdict')!.className).not.toContain('not-ready');
    await act(async () => { fpInput.value = expected.store; fpInput.dispatchEvent(new Event('input', { bubbles: true })); });
    await act(tick);
    expect(root.querySelector('.verdict')!.className).toContain('not-ready');
  });

  it('shows a friendly error for a file that is not an APK', async () => {
    await act(() => { render(<App />, root); });
    const input = root.querySelector('input[type=file]') as HTMLInputElement;
    const file = new File(['hello'], 'notes.apk');
    Object.defineProperty(input, 'files', { value: [file] });
    await act(async () => { input.dispatchEvent(new Event('change', { bubbles: true })); });
    await until(() => root.textContent!.includes('notes.apk'));
    expect(root.querySelector('.card-error')).not.toBeNull();
  });
});
