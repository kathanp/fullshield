import { isSeverity, type Severity } from '../core/finding.js';

/** Map a tool label onto the Finding scale. Unknown labels stay info. */
export function mapLabeledSeverity(label: string): Severity {
  const key = label.toLowerCase();
  if (key === 'critical') {return 'critical';}
  if (key === 'high' || key === 'error') {return 'high';}
  if (key === 'moderate' || key === 'medium' || key === 'warning') {return 'medium';}
  if (key === 'low' || key === 'note') {return 'low';}
  if (key === 'info' || key === 'none') {return 'info';}
  return 'info';
}

export function mapSemgrepSeverity(label: string): Severity {
  if (label.toUpperCase() === 'ERROR') {return 'high';}
  if (label.toUpperCase() === 'WARNING') {return 'medium';}
  if (label.toUpperCase() === 'INFO') {return 'low';}
  return mapLabeledSeverity(label);
}

export function sarifSeverity(
  level: string,
  named: string | undefined,
): { severity: Severity; external: string } {
  if (named !== undefined && isSeverity(named.toLowerCase())) {
    return { severity: named.toLowerCase() as Severity, external: named };
  }
  return { severity: mapLabeledSeverity(level), external: level };
}
