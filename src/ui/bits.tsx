import { useState } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { colonHex, type CertInfo, type Severity } from '../core';
import { ACCEPT } from './util';

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      class="copy"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard blocked; the value is still selectable */
        }
      }}
    >
      {done ? 'Copied' : label}
    </button>
  );
}

export function Fingerprint({ sha256 }: { sha256: string }) {
  return (
    <div class="fp">
      <code class="fp-value">{colonHex(sha256)}</code>
      <span class="fp-actions">
        <CopyButton text={colonHex(sha256)} label="Copy" />
        <CopyButton text={sha256.toLowerCase()} label="Copy for API" />
      </span>
    </div>
  );
}

export function CertSummary({ cert }: { cert: CertInfo }) {
  const pk = cert.publicKey;
  const key = pk.algorithm === 'EC' ? `EC ${pk.curve}` : `${pk.algorithm}${pk.bits ? ` ${pk.bits}-bit` : ''}`;
  return (
    <dl class="cert">
      <dt>Subject</dt>
      <dd>{cert.subject || '—'}</dd>
      <dt>Key</dt>
      <dd>
        {key} · {cert.signatureAlgorithm}
      </dd>
      <dt>Valid</dt>
      <dd>
        {cert.notBefore?.slice(0, 10) ?? '?'} → {cert.notAfter?.slice(0, 10) ?? '?'}
      </dd>
      <dt>SHA-1</dt>
      <dd>
        <code class="small">{colonHex(cert.sha1)}</code>
      </dd>
    </dl>
  );
}

export function Badge({ tone, children }: { tone: Severity | 'ok' | 'muted'; children: ComponentChildren }) {
  return <span class={`badge badge-${tone}`}>{children}</span>;
}

export function DropZone({ onFiles, multiple = true, hint }: { onFiles: (f: File[]) => void; multiple?: boolean; hint: string }) {
  const [over, setOver] = useState(false);
  return (
    <label
      class={`drop ${over ? 'over' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        const files = [...(e.dataTransfer?.files ?? [])];
        if (files.length) onFiles(multiple ? files : files.slice(0, 1));
      }}
    >
      <input
        type="file"
        accept={ACCEPT}
        multiple={multiple}
        onChange={(e) => {
          const input = e.currentTarget;
          const files = [...(input.files ?? [])];
          if (files.length) onFiles(files);
          input.value = '';
        }}
      />
      <strong>{multiple ? 'Drop APK, AAB or APK-set files here' : 'Drop your proof APK here'}</strong>
      <span>{hint}</span>
    </label>
  );
}
