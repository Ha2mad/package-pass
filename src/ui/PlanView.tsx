import { buildPlan, planToApiScript, planToCsv, planToJson, ROLE_LABEL, type ArtifactReport } from '../core';
import { Badge, Fingerprint } from './bits';
import { download } from './util';

const ROLE_TONE = { signing: 'ok', 'earlier-rotation': 'muted', upload: 'warn', debug: 'error' } as const;

export function PlanView({ reports }: { reports: ArtifactReport[] }) {
  const plan = buildPlan(reports);
  if (!plan.packages.length) return null;
  const shared = plan.keyGroups.filter((g) => g.packages.length > 1);
  const stamp = new Date().toISOString().slice(0, 10);
  return (
    <section class="plan">
      <div class="plan-head">
        <div>
          <h2>Registration plan</h2>
          <p class="muted">
            {plan.packages.length} package{plan.packages.length === 1 ? '' : 's'} · {plan.keyGroups.length} registrable key
            {plan.keyGroups.length === 1 ? '' : 's'}. Add every key that ships your app (your own builds and any store that re-signs) under the same package name.
          </p>
        </div>
        <div class="actions">
          <button type="button" onClick={() => download(`package-pass-plan-${stamp}.csv`, planToCsv(plan), 'text/csv')}>
            Export CSV
          </button>
          <button type="button" onClick={() => download(`package-pass-plan-${stamp}.json`, planToJson(plan), 'application/json')}>
            Export JSON
          </button>
          <button type="button" class="primary" onClick={() => download('register.sh', planToApiScript(plan), 'text/x-shellscript')}>
            API script
          </button>
        </div>
      </div>

      {shared.length > 0 && (
        <div class="callout">
          {shared.map((g) => (
            <p key={g.sha256}>
              <strong>{g.cert.subjectCN ?? 'One key'}</strong> signs {g.packages.length} packages ({g.packages.join(', ')}). Prove ownership of it once; the console
              skips the proof step for that key on your other packages.
            </p>
          ))}
        </div>
      )}

      <table class="plan-table">
        <thead>
          <tr>
            <th>Package</th>
            <th>Key</th>
            <th>Role</th>
            <th>Seen in</th>
          </tr>
        </thead>
        <tbody>
          {plan.packages.flatMap((p) =>
            p.keys.map((k, i) => (
              <tr key={p.packageName + k.sha256} class={i === 0 ? 'first' : ''}>
                <td>
                  {i === 0 && (
                    <>
                      <strong>{p.packageName}</strong>
                      {p.versions.length > 0 && <div class="muted small">{p.versions.join(', ')}</div>}
                    </>
                  )}
                </td>
                <td>
                  <Fingerprint sha256={k.sha256} />
                  <div class="muted small">{k.cert.subject}</div>
                </td>
                <td>
                  <Badge tone={ROLE_TONE[k.role]}>{ROLE_LABEL[k.role]}</Badge>
                </td>
                <td class="small">{k.sources.join(', ')}</td>
              </tr>
            )),
          )}
        </tbody>
      </table>
      {plan.unreadable.length > 0 && <p class="muted">Not in the plan (no package or key found): {plan.unreadable.join(', ')}</p>}
    </section>
  );
}
