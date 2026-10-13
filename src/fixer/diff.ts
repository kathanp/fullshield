/** Minimal unified diff for a single-file replacement (display + apply). */
export function unifiedDiff(filename: string, before: string, after: string): string {
  if (before === after) return '';
  const oldLines = before.split('\n');
  const newLines = after.split('\n');
  const hunks: string[] = [`--- a/${filename}`, `+++ b/${filename}`];
  hunks.push(`@@ -1,${oldLines.length} +1,${newLines.length} @@`);
  for (const line of oldLines) hunks.push(`-${line}`);
  for (const line of newLines) hunks.push(`+${line}`);
  return hunks.join('\n');
}

export function applyReplacement(before: string, after: string): string {
  return after;
}
