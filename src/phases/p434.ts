/**
 * Phase 434. Offline HTML report.
 * Off unless FULLSHIELD_EXPERIMENTAL_HTMLRPT=1.
 * Flag off: the command errors with FS-E and writes nothing.
 * The report is static: no script, no external stylesheet, no image URL.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HTMLRPT';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/g;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface HtmlFinding {
  title: string;
  message: string;
  file: string;
  line: number;
  secret?: string;
}

export interface HtmlWrite {
  exitCode: number;
  code?: 'FS-E';
  wrote: boolean;
  html: string | null;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function redact(text: string, secret: string | undefined): string {
  const without = secret === undefined ? text : text.split(secret).join('****');
  return without.replace(SECRET, (token) => `${token.slice(0, 4)}****`);
}

function renderHtml(findings: readonly HtmlFinding[]): string {
  const rows = findings
    .map((finding) => {
      const title = escapeHtml(redact(finding.title, finding.secret));
      const message = escapeHtml(redact(finding.message, finding.secret));
      return `<section><h2>${title}</h2><p>${message}</p><p>${escapeHtml(finding.file)}:${finding.line}</p></section>`;
    })
    .join('');
  return `<!DOCTYPE html><html><head><title>FullShield</title><style>body{font-family:sans-serif}</style></head><body><h1>Findings</h1>${rows}</body></html>`;
}

export function writeHtml(findings: readonly HtmlFinding[], htmlPath: string | undefined): HtmlWrite {
  if (!enabled()) {
    return { exitCode: 1, code: 'FS-E', wrote: false, html: null };
  }
  if (htmlPath === undefined) {
    return { exitCode: 1, code: 'FS-E', wrote: false, html: null };
  }
  return { exitCode: 0, wrote: true, html: renderHtml(findings) };
}
