import { readFile } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { join } from 'node:path';

export interface NotifySummary {
  total: number;
  bySeverity: Record<string, number>;
  version?: string;
  cwd?: string;
}

export async function loadLastScan(cwd: string): Promise<NotifySummary> {
  const raw = JSON.parse(await readFile(join(cwd, '.fullshield', 'last-scan.json'), 'utf8')) as {
    summary?: NotifySummary;
    metadata?: { version?: string; cwd?: string };
  };
  if (raw.summary === undefined) throw new Error('last scan file has no summary');
  return { ...raw.summary, version: raw.metadata?.version, cwd: raw.metadata?.cwd ?? cwd };
}

export function formatSummary(summary: NotifySummary): string {
  const parts = Object.entries(summary.bySeverity)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${n} ${k}`);
  return `FullShield v${summary.version ?? '?'} — ${summary.total} finding(s)${parts.length > 0 ? `: ${parts.join(', ')}` : ''}`;
}

export async function postJson(url: string, body: unknown): Promise<void> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`notifier webhook returned ${res.status}`);
}

export async function notifySlack(webhookUrl: string, summary: NotifySummary): Promise<void> {
  await postJson(webhookUrl, { text: formatSummary(summary) });
}

export async function notifyWebhook(url: string, summary: NotifySummary): Promise<void> {
  await postJson(url, { text: formatSummary(summary), summary });
}

export async function notifyEmail(options: {
  host: string;
  port: number;
  from: string;
  to: string;
  summary: NotifySummary;
}): Promise<void> {
  const text = formatSummary(options.summary);
  await new Promise<void>((resolve, reject) => {
    const sock = createConnection({ host: options.host, port: options.port }, () => {
      const payload =
        `EHLO localhost\r\nMAIL FROM:<${options.from}>\r\nRCPT TO:<${options.to}>\r\nDATA\r\n` +
        `Subject: FullShield scan\r\n\r\n${text}\r\n.\r\nQUIT\r\n`;
      sock.write(payload);
    });
    sock.setTimeout(3000);
    sock.on('timeout', () => {
      sock.destroy();
      reject(new Error('SMTP timeout'));
    });
    sock.on('error', reject);
    sock.on('data', () => {
      /* drain */
    });
    sock.on('end', () => resolve());
    sock.on('close', () => resolve());
  });
}
