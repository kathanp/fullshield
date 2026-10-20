/** Reset lastIndex so a shared `/g` regex cannot skip the next file or line. */
export function everyMatch(re: RegExp, text: string): RegExpExecArray[] {
  re.lastIndex = 0;
  return [...text.matchAll(re)] as RegExpExecArray[];
}

/** Mask a secret for display: first 4 chars + '****' (spec §4.2). */
export function maskSecret(secret: string): string {
  return `${secret.slice(0, 4)}****`;
}

/**
 * Fold adjacent string-literal concatenation in a source line so secrets
 * assembled as 'AKIA' + 'XXXX...' (the recommended fixture style, spec §14)
 * are still detected: removes `' + '` between two quote characters.
 */
export function foldStringConcat(line: string): string {
  return line.replace(/(["'`])\s*\+\s*(["'`])/g, '');
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) {return 0;}
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
