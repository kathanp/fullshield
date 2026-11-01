import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ScanResult } from '../core/engine.js';
import { lineIndependentFingerprint } from '../core/fingerprint.js';
import type { Finding, Severity } from '../core/finding.js';
import { redactScan } from './redact.js';

export const SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') {return 'error';}
  if (severity === 'medium') {return 'warning';}
  return 'note';
}

function uri(file: string | undefined): string {
  return (file ?? '').replace(/\\/g, '/');
}

function sarifV2(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SARIF_V2 === '1';
}

function ruleMarkdown(ruleId: string): string | undefined {
  const path = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'rules', `${ruleId}.md`);
  if (!existsSync(path)) {return undefined;}
  return readFileSync(path, 'utf8').slice(0, 2048);
}

function relatedLocations(finding: Finding): unknown[] | undefined {
  if (finding.dependencyPath === undefined || finding.dependencyPath.length === 0) {return undefined;}
  return finding.dependencyPath.map((step) => ({
    message: { text: step },
    physicalLocation: {
      artifactLocation: { uri: uri(finding.file) },
      ...(finding.line !== undefined ? { region: { startLine: finding.line } } : {}),
    },
  }));
}

/** SARIF 2.1.0 report for GitHub Code Scanning and other consumers. */
const INFORMATION_URI = 'https://github.com/kathanp/fullshield';

function sarifResult(finding: Finding, v2: boolean): Record<string, unknown> {
  const region: { startLine?: number; startColumn?: number } = {};
  if (finding.line !== undefined) {region.startLine = finding.line;}
  if (finding.column !== undefined) {region.startColumn = finding.column + 1;}
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
  const related = v2 ? relatedLocations(finding) : undefined;
  const codeFlows =
    finding.trace !== undefined && finding.trace.length > 0
      ? [
          {
            threadFlows: [
              {
                locations: finding.trace.map((step) => ({
                  location: {
                    message: { text: step.note },
                    physicalLocation: {
                      artifactLocation: { uri: uri(step.file) },
                      ...(step.line !== undefined ? { region: { startLine: step.line } } : {}),
                    },
                  },
                })),
              },
            ],
          },
        ]
      : undefined;
  return {
    ruleId: finding.ruleId,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: location,
    ...(codeFlows !== undefined ? { codeFlows } : {}),
    ...(v2
      ? {
          partialFingerprints: { 'fullshield/v1': lineIndependentFingerprint(finding) },
          ...(related !== undefined ? { relatedLocations: related } : {}),
          ...(finding.module === 'deps' && finding.reachability !== undefined
            ? { properties: { reachability: finding.reachability } }
            : {}),
        }
      : {}),
  };
}

export function renderSarifReport(input: ScanResult): string {
  const result = redactScan(input);
  const v2 = sarifV2();
  const rules = new Map<string, Record<string, unknown>>();
  for (const finding of result.findings) {
    if (!rules.has(finding.ruleId)) {
      const markdown = v2 ? ruleMarkdown(finding.ruleId) : undefined;
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.title },
        ...(markdown !== undefined ? { help: { markdown } } : {}),
        ...(v2 ? { properties: { precision: 'unreviewed' } } : {}),
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
            informationUri: INFORMATION_URI,
            rules: [...rules.values()],
          },
        },
        results: result.findings.map((finding: Finding) => sarifResult(finding, v2)),
      },
    ],
  };
  return JSON.stringify(doc, null, 2);
}

function validateResult(prefix: string, result: unknown, errors: string[]): void {
  if (typeof result !== 'object' || result === null) {
    errors.push(`${prefix} must be an object`);
    return;
  }
  const res = result as Record<string, unknown>;
  const message = res.message as Record<string, unknown> | undefined;
  if (typeof message?.text !== 'string' && typeof message?.id !== 'string') {
    errors.push(`${prefix}.message.text or message.id is required`);
  }
}

function validateRun(index: number, run: unknown, errors: string[]): void {
  if (typeof run !== 'object' || run === null) {
    errors.push(`runs[${index}] must be an object`);
    return;
  }
  const record = run as Record<string, unknown>;
  const tool = record.tool as Record<string, unknown> | undefined;
  const driver = tool?.driver as Record<string, unknown> | undefined;
  if (typeof driver?.name !== 'string' || driver.name.length === 0) {
    errors.push(`runs[${index}].tool.driver.name is required`);
  }
  if (!Array.isArray(record.results)) {
    errors.push(`runs[${index}].results must be an array`);
    return;
  }
  for (const [j, result] of record.results.entries()) {
    validateResult(`runs[${index}].results[${j}]`, result, errors);
  }
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
  if (root.version !== '2.1.0') {errors.push('version must be "2.1.0"');}
  if (!Array.isArray(root.runs)) {
    errors.push('runs must be an array');
    return errors;
  }
  for (const [i, run] of root.runs.entries()) {
    validateRun(i, run, errors);
  }
  return errors;
}
