/**
 * Phase 397. CSP suggestion from literals.
 * Off unless FULLSHIELD_EXPERIMENTAL_CSPBUILD=1.
 * The suggestion is a comment. It is not installed as a header.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CSPBUILD';

export const LITERAL_NOTE = 'The suggestion is the set of literals, not a policy that was tested.';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CspSuggestion {
  section: string;
  headerWritten: false;
}

function withoutComments(text: string): string {
  const parts: string[] = [];
  let index = 0;
  while (index < text.length) {
    if (text.startsWith('<!--', index)) {
      const end = text.indexOf('-->', index + 4);
      if (end === -1) {
        break;
      }
      index = end + 3;
      continue;
    }
    parts.push(text[index] ?? '');
    index += 1;
  }
  return parts.join('');
}

function hostsFrom(text: string): { hosts: string[]; inline: boolean; dynamic: boolean } {
  const hosts: string[] = [];
  const stripped = withoutComments(text);
  const inline = /\son[a-z]+\s*=/i.test(stripped) || /<script(?![^>]*\bsrc=)[^>]*>/i.test(stripped);
  const dynamic = /src=\{/.test(text) || /href=\{/.test(text);
  for (const match of stripped.matchAll(/\b(?:src|href)\s*=\s*['"](https:\/\/[^'"]+)['"]/gi)) {
    const raw = match[1];
    if (raw === undefined) {
      continue;
    }
    try {
      const host = new URL(raw).host;
      if (!hosts.includes(host)) {
        hosts.push(host);
      }
    } catch {
      continue;
    }
  }
  return { hosts, inline, dynamic };
}

export function cspSuggestion(files: readonly { name: string; text: string }[]): CspSuggestion | null {
  if (!enabled()) {
    return null;
  }
  const hosts: string[] = [];
  let inline = false;
  let dynamic = false;
  for (const file of files) {
    const found = hostsFrom(file.text);
    inline = inline || found.inline;
    dynamic = dynamic || found.dynamic;
    for (const host of found.hosts) {
      if (!hosts.includes(host)) {
        hosts.push(host);
      }
    }
  }
  const lines = [
    'Content-Security-Policy suggestion',
    LITERAL_NOTE,
    `script-src ${hosts.join(' ') || "'none'"}`,
  ];
  if (inline) {
    lines.push("omit 'unsafe-inline': an inline handler blocks a strict policy");
  } else {
    lines.push("script-src does not include 'unsafe-inline'");
  }
  if (dynamic) {
    lines.push("a dynamic script URL was not static; 'strict-dynamic' is left unset");
  }
  return { section: lines.join('\n'), headerWritten: false };
}
