import { detectKind } from './detect.js';
import { IngestError } from './error.js';
import type { IngestItem } from './item.js';
import { parseNpm } from './parse-npm.js';
import { parseOsv } from './parse-osv.js';
import { parseSarif } from './parse-sarif.js';
import { parseSemgrep } from './parse-semgrep.js';

export function parseIngestText(file: string, text: string): IngestItem[] {
  if (text.trim().length === 0) {throw new IngestError(file, 'empty file');}
  let doc: unknown;
  try {
    doc = JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'invalid JSON';
    throw new IngestError(file, message);
  }
  const kind = detectKind(doc);
  if (kind === 'sarif') {return parseSarif(file, doc);}
  if (kind === 'npm') {return parseNpm(file, doc);}
  if (kind === 'osv') {return parseOsv(file, doc);}
  if (kind === 'semgrep') {return parseSemgrep(file, doc);}
  throw new IngestError(file, 'unrecognized ingest schema');
}
