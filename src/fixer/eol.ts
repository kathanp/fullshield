export type Eol = '\r\n' | '\n';

/** Detect the dominant newline of a file (`\r\n` wins if any CRLF is present). */
export function detectEol(text: string): Eol {
  return text.includes('\r\n') ? '\r\n' : '\n';
}

/** Collapse `\r\n` and bare `\r` to `\n` so diffs and compares are autocrlf-independent. */
export function normalizeNewlines(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

/** Rewrite a `\n`-normalized string using the original file's newline. */
export function applyEol(text: string, eol: Eol): string {
  const normalized = normalizeNewlines(text);
  return eol === '\n' ? normalized : normalized.replace(/\n/g, '\r\n');
}
