/**
 * Phase 425. SARIF fixes.
 * Off unless FULLSHIELD_EXPERIMENTAL_SARIFFIX=1.
 * Flag off: the document is the base SARIF with no fixes property.
 */
import { validateSarif21 } from '../reporters/sarif.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SARIFFIX';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/g;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SarifEdit {
  ruleId: string;
  message: string;
  file: string;
  line: number;
  patch: string;
  disposition: 'safe' | 'review';
  refused: boolean;
}

interface SarifResult {
  ruleId: string;
  level: 'warning';
  message: { text: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }>;
  fixes?: Array<{ description: { text: string }; artifactChanges: unknown[] }>;
}

function scrub(text: string): string {
  return text.replace(SECRET, (token) => `${token.slice(0, 4)}****`);
}

function resultOf(edit: SarifEdit, withFix: boolean): SarifResult {
  const row: SarifResult = {
    ruleId: edit.ruleId,
    level: 'warning',
    message: { text: scrub(edit.message) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: edit.file },
          region: { startLine: edit.line },
        },
      },
    ],
  };
  if (withFix && !edit.refused) {
    row.fixes = [
      {
        description: { text: edit.disposition },
        artifactChanges: [
          {
            artifactLocation: { uri: edit.file },
            replacements: [{ deletedRegion: { startLine: edit.line }, insertedContent: { text: scrub(edit.patch) } }],
          },
        ],
      },
    ];
  }
  return row;
}

function document(edits: readonly SarifEdit[], withFix: boolean): Record<string, unknown> {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'FullShield' } },
        results: edits.map((edit) => resultOf(edit, withFix)),
      },
    ],
  };
}

export function renderSarif(edits: readonly SarifEdit[]): string {
  return JSON.stringify(document(edits, enabled()), null, 2);
}

export function sarifErrors(text: string): string[] {
  return validateSarif21(JSON.parse(text) as unknown);
}
