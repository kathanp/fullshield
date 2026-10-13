import type { ScanResult } from '../core/engine.js';
import type { Finding, Severity } from '../core/finding.js';

const SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function uri(file: string | undefined): string {
  return (file ?? '').replace(/\\/g, '/');
}

/** SARIF 2.1.0 report for GitHub Code Scanning and other consumers. */
export function renderSarifReport(result: ScanResult): string {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
  for (const finding of result.findings) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.title },
      });
    }
  }

  const doc = {
    $schema: SCHEMA_URI,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'FullShield',
            version: result.metadata.version,
            informationUri: 'https://github.com/fullshield/fullshield',
            rules: [...rules.values()],
          },
        },
        results: result.findings.map((finding: Finding) => {
          const region: { startLine?: number; startColumn?: number } = {};
          if (finding.line !== undefined) region.startLine = finding.line;
          if (finding.column !== undefined) region.startColumn = finding.column + 1;
          const location =
            finding.file !== undefined
              ? [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: uri(finding.file) },
                      ...(Object.keys(region).length > 0 ? { region } : {}),
                    },
                  },
                ]
              : [];
          return {
            ruleId: finding.ruleId,
            level: sarifLevel(finding.severity),
            message: { text: finding.message },
            locations: location,
          };
        }),
      },
    ],
  };
  return JSON.stringify(doc, null, 2);
}

/**
 * Structural SARIF 2.1.0 schema check for the documents we emit.
 * Returns an empty array when valid; otherwise human-readable errors.
 */
export function validateSarif21(doc: unknown): string[] {
  const errors: string[] = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['SARIF document must be an object'];
  }
  const root = doc as Record<string, unknown>;
  if (root.version !== '2.1.0') errors.push('version must be "2.1.0"');
  if (!Array.isArray(root.runs)) {
    errors.push('runs must be an array');
    return errors;
  }
  for (const [i, run] of root.runs.entries()) {
    if (typeof run !== 'object' || run === null) {
      errors.push(`runs[${i}] must be an object`);
      continue;
    }
    const r = run as Record<string, unknown>;
    const tool = r.tool as Record<string, unknown> | undefined;
    const driver = tool?.driver as Record<string, unknown> | undefined;
    if (typeof driver?.name !== 'string' || driver.name.length === 0) {
      errors.push(`runs[${i}].tool.driver.name is required`);
    }
    if (!Array.isArray(r.results)) {
      errors.push(`runs[${i}].results must be an array`);
      continue;
    }
    for (const [j, result] of r.results.entries()) {
      if (typeof result !== 'object' || result === null) {
        errors.push(`runs[${i}].results[${j}] must be an object`);
        continue;
      }
      const res = result as Record<string, unknown>;
      const message = res.message as Record<string, unknown> | undefined;
      if (typeof message?.text !== 'string' && typeof message?.id !== 'string') {
        errors.push(`runs[${i}].results[${j}].message.text or message.id is required`);
      }
    }
  }
  return errors;
}
