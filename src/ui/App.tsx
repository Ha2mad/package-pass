import { useState } from 'preact/hooks';
import type { ArtifactReport } from '../core';
import { ArtifactCard } from './ArtifactCard';
import { DropZone } from './bits';
import { Guide } from './Guide';
import { PlanView } from './PlanView';
import { ProofCheck } from './ProofCheck';
import { loadSamples, readFiles } from './util';

type Tab = 'keys' | 'proof' | 'guide';

export function App() {
  const [tab, setTab] = useState<Tab>('keys');
  const [reports, setReports] = useState<ArtifactReport[]>([]);
  const [busy, setBusy] = useState(false);

  const add = async (p: Promise<ArtifactReport[]>) => {
    setBusy(true);
    try {
      const next = await p;
      setReports((cur) => [...cur.filter((c) => !next.some((n) => n.fileName === c.fileName)), ...next]);
    } finally {
      setBusy(false);
    }
  };

  const tabs: [Tab, string][] = [
    ['keys', 'Packages & keys'],
    ['proof', 'Proof APK check'],
    ['guide', 'Guide'],
  ];

  return (
    <div class="shell">
      <header class="top">
        <div class="brand">
          <img src="./icon.svg" alt="" width="40" height="40" />
          <div>
            <h1>Package Pass</h1>
            <p>Get your Android apps through developer verification. Every package name and signing key, checked in your browser.</p>
          </div>
        </div>
        <span class="privacy">🔒 Files never leave this tab</span>
      </header>

      <nav class="tabs" role="tablist">
        {tabs.map(([id, label]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} class={tab === id ? 'active' : ''} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </nav>

      <main>
        {tab === 'keys' && (
          <>
            <DropZone onFiles={(f) => add(readFiles(f))} hint=".apk · .aab · .apks · .xapk: drop your own builds and the APKs stores ship, all at once." />
            <div class="toolbar">
              <button type="button" class="link" onClick={() => add(loadSamples())}>
                Load sample files
              </button>
              {reports.length > 0 && (
                <button type="button" class="link" onClick={() => setReports([])}>
                  Clear all
                </button>
              )}
              {busy && <span class="muted">Reading…</span>}
            </div>
            {reports.length === 0 && !busy && (
              <div class="empty">
                <p>
                  Package Pass reads each file's <strong>package name</strong> and the <strong>SHA-256 of the signing key</strong> Android checks. It verifies v2/v3
                  signatures, follows key rotation, spots debug and upload keys, and builds one registration plan across all your apps and stores.
                </p>
              </div>
            )}
            <PlanView reports={reports} />
            <div class="cards">
              {reports.map((r) => (
                <ArtifactCard key={r.fileName} r={r} onRemove={() => setReports((cur) => cur.filter((c) => c !== r))} />
              ))}
            </div>
          </>
        )}
        {tab === 'proof' && <ProofCheck />}
        {tab === 'guide' && <Guide />}
      </main>
      <footer>
        MIT licensed · <a href="https://github.com/Ha2mad/package-pass">Source</a> · Not affiliated with Google. Always confirm in the Android Developer Console.
      </footer>
    </div>
  );
}
