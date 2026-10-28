import { useState } from 'preact/hooks';
import type { ArtifactReport } from '../core';
import { Badge, CertSummary, Fingerprint } from './bits';
import { formatBytes } from './util';

const KIND_LABEL = { apk: 'APK', aab: 'App bundle', 'apk-set': 'APK set' } as const;

export function ArtifactCard({ r, onRemove }: { r: ArtifactReport; onRemove?: () => void }) {
  const [open, setOpen] = useState(false);
  const m = r.manifest;
  const worst = r.findings.some((f) => f.severity === 'error') ? 'error' : r.findings.some((f) => f.severity === 'warn') ? 'warn' : 'ok';
  return (
    <article class={`card card-${worst}`}>
      <header class="card-head">
        <div>
          <h3>{m.packageName ?? r.fileName}</h3>
          <p class="muted">
            {r.fileName} · {formatBytes(r.size)}
            {m.versionName || m.versionCode ? ` · v${m.versionName ?? ''}${m.versionCode ? ` (${m.versionCode})` : ''}` : ''}
            {m.minSdk ? ` · minSdk ${m.minSdk}` : ''}
            {m.targetSdk ? ` · targetSdk ${m.targetSdk}` : ''}
          </p>
        </div>
        <div class="chips">
          <Badge tone="muted">{KIND_LABEL[r.kind]}</Badge>
          {r.schemes.map((s) => (
            <Badge tone="muted" key={s}>
              {s}
            </Badge>
          ))}
          {r.integrity.some((i) => i.status === 'failed') ? (
            <Badge tone="error">signature broken</Badge>
          ) : r.integrity.some((i) => i.status === 'verified') ? (
            <Badge tone="ok">signature verified</Badge>
          ) : null}
          {onRemove && (
            <button type="button" class="link" onClick={onRemove} aria-label={`Remove ${r.fileName}`}>
              Remove
            </button>
          )}
        </div>
      </header>

      {r.currentCert && (
        <section>
          <h4>{r.kind === 'aab' ? 'Bundle signing key (usually your upload key)' : 'Signing key SHA-256: register this'}</h4>
          <Fingerprint sha256={r.currentCert.sha256} />
          <CertSummary cert={r.currentCert} />
        </section>
      )}

      {r.lineage.length > 1 && (
        <section>
          <h4>Rotation lineage (oldest first)</h4>
          <ol class="lineage">
            {r.lineage.map((l) => (
              <li key={l.cert.sha256}>
                <code class="small">{l.cert.sha256.slice(0, 24)}…</code> {l.cert.subjectCN ?? l.cert.subject}
              </li>
            ))}
          </ol>
        </section>
      )}

      {r.findings.length > 0 && (
        <ul class="findings">
          {r.findings.map((f) => (
            <li key={f.id + f.detail} class={`finding finding-${f.severity}`}>
              <strong>{f.title}</strong> <span>{f.detail}</span>
            </li>
          ))}
        </ul>
      )}

      {r.signers.length > 0 && (
        <details open={open} onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
          <summary>All signatures ({r.signers.length})</summary>
          <table class="mini">
            <thead>
              <tr>
                <th>Scheme</th>
                <th>Certificate SHA-256</th>
                <th>SDK range</th>
                <th>Check</th>
              </tr>
            </thead>
            <tbody>
              {r.signers.map((s, i) => {
                const integ = r.integrity.find((x) => x.scheme === s.scheme);
                return (
                  <tr key={i}>
                    <td>{s.scheme}</td>
                    <td>
                      <code class="small">{s.cert.sha256}</code>
                    </td>
                    <td>{s.minSdk !== null ? `${s.minSdk}–${s.maxSdk === 0x7fffffff ? '∞' : s.maxSdk}` : 'all'}</td>
                    <td title={integ?.detail}>{s.scheme === 'v1' ? 'present' : (integ?.status ?? '—')}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {r.extras.length > 0 && <p class="muted">Also in signing block: {r.extras.join(', ')}</p>}
        </details>
      )}
    </article>
  );
}
