// Captures README screenshots from a production build using headless Chromium.
// Usage: npm run build && npm run screenshots
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const PORT = 4182;
const URL = `http://127.0.0.1:${PORT}/`;
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--port', String(PORT), '--strictPort', '--host', '127.0.0.1'], { stdio: 'pipe' });
const errors = [];
const expected = JSON.parse(readFileSync('tests/fixtures/expected-fingerprints.json', 'utf8'));

try {
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(URL)).ok) break; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
  const open = async (theme, height = 1000) => {
    const page = await browser.newPage({ viewport: { width: 1440, height }, colorScheme: theme });
    page.on('pageerror', (e) => errors.push(String(e)));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    await page.goto(URL);
    return page;
  };

  let page = await open('light', 1400);
  await page.getByRole('button', { name: 'Load sample files' }).click();
  await page.getByText('com.axenova.beta').first().waitFor();
  await page.screenshot({ path: 'docs/screenshot-plan.png' });
  await page.locator('.card', { hasText: 'beta-rotated.apk' }).first().scrollIntoViewIfNeeded();
  await page.locator('.card', { hasText: 'beta-rotated.apk' }).first().screenshot({ path: 'docs/screenshot-artifact.png' });
  await page.close();

  page = await open('dark', 1000);
  await page.getByRole('tab', { name: 'Proof APK check' }).click();
  await page.getByRole('button', { name: 'Try the sample proof APK' }).click();
  await page.locator('.verdict').waitFor();
  await page.getByLabel('SHA-256 fingerprint you added in the console').fill(expected.release);
  await page.getByLabel('Snippet from the console (optional)').fill('FIXTURE0TOKEN0ALPHA0000000');
  await page.locator('.verdict.ready').waitFor();
  await page.screenshot({ path: 'docs/screenshot-proof.png' });
  await page.close();
  await browser.close();
} finally {
  server.kill();
}
if (errors.length) {
  console.error('Browser errors:\n' + errors.join('\n'));
  process.exit(1);
}
console.log('Screenshots written to docs/');
process.exit(0);
