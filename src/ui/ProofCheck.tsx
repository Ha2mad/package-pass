import { useState } from 'preact/hooks';
import { preflight, type ArtifactReport } from '../core';
import { DropZone } from './bits';
import { ArtifactCard } from './ArtifactCard';
import { loadSamples, readFiles } from './util';

const ICON = { pass: '✔', fail: '✖', warn: '!', skip: '–' } as const;

export function ProofCheck() {
  const [report, setReport] = useState<ArtifactReport | null>(null);
  const [pkg, setPkg] = useState('');
  const [fp, setFp] = useState('');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async (p: Promise<ArtifactReport[]>) => {
    setBusy(true);
    try {
      const [r] = await p;
      setReport(r);
      if (!pkg && r.manifest.packageName) setPkg(r.manifest.packageName);
    } finally {
      setBusy(false);
    }
  };

  const result = report ? preflight(report, { packageName: pkg, fingerprint: fp, token }) : null;

  return (
    <div class="proof">
      <p class="lead">
        Existing package names need proof that you hold the private key: an APK with the console's snippet in <code>assets/adi-registration.properties</code>, signed with
        that key. Check it here before you upload so a rejected upload doesn't cost you a round trip.
      </p>
      <div class="proof-grid">
        <form class="inputs" onSubmit={(e) => e.preventDefault()}>
          <label>
            Package name you are registering
            <input value={pkg} onInput={(e) => setPkg(e.currentTarget.value)} placeholder="com.example.app" spellcheck={false} />
          </label>
          <label>
            SHA-256 fingerprint you added in the console
            <input value={fp} onInput={(e) => setFp(e.currentTarget.value)} placeholder="AB:CD:… or abcd…" spellcheck={false} />
          </label>
          <label>
            Snippet from the console (optional)
            <input value={token} onInput={(e) => setToken(e.currentTarget.value)} placeholder="Paste the snippet / verificationToken" spellcheck={false} />
          </label>
          <DropZone multiple={false} onFiles={(f) => load(readFiles(f))} hint="Read locally. Nothing is uploaded." />
          <button
            type="button"
            class="link"
            onClick={() => {
              setPkg('com.axenova.alpha');
              setFp('3A:C4:49:52:17:3E:59:64:BB:27:63:72:95:DD:FF:83:6F:B5:14:E4:7D:45:A5:F5:A9:43:6D:04:EC:6A:66:A0');
              setToken('FIXTURE0TOKEN0ALPHA0000000');
              load(loadSamples(['alpha-proof.apk']));
            }}
          >
            Try the sample proof APK
          </button>
        </form>
        <div class="checklist" aria-live="polite">
          {busy && <p class="muted">Reading…</p>}
          {!report && !busy && <p class="muted">Results appear here.</p>}
          {result && (
            <>
              <div class={`verdict ${result.ready ? 'ready' : 'not-ready'}`}>{result.ready ? 'Ready to upload' : 'Not ready yet'}</div>
              <ul>
                {result.checks.map((c) => (
                  <li key={c.id} class={`check check-${c.status}`}>
                    <span class="icon" aria-hidden="true">
                      {ICON[c.status]}
                    </span>
                    <div>
                      <strong>{c.title}</strong>
                      <p>{c.detail}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
      {report && <ArtifactCard r={report} />}
    </div>
  );
}
