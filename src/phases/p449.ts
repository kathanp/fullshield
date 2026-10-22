/**
 * Phase 449. Data-only rule plugins.
 * Off unless FULLSHIELD_EXPERIMENTAL_RULEPLUGIN=1.
 * Flag off: the plugin directory is not applied and no USER finding is returned.
 * Plugins are JSON only. Rule ids must start with USER-.
 */
import { isAbsolute, relative, resolve, sep } from 'node:path';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RULEPLUGIN';

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PluginDoc {
  ruleId: string;
  sources: string[];
  sinks: Array<{ pattern: string; sinkClass: string }>;
  sanitizers: Array<{ pattern: string; clears: string[] }>;
}

export interface PluginFinding {
  ruleId: string;
  file: string;
  line: number;
  severity: 'high';
  message: string;
  witness: { pluginPath: string; cleared: string | null };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

export function loadPlugin(dir: string, relativePath: string, text: string): PluginDoc {
  if (relativePath.endsWith('.js') || text.includes('require(') || /\bimport\s/.test(text)) {
    throw new FsError('plugin must be JSON');
  }
  const root = resolve(dir);
  const target = resolve(dir, relativePath);
  const rel = relative(root, target);
  if (rel.startsWith('..') || isAbsolute(rel) || rel.split(sep).includes('..')) {
    throw new FsError('plugin path escapes the directory');
  }
  const parsed = JSON.parse(text) as unknown;
  const record = asRecord(parsed);
  if (record === null || typeof record.ruleId !== 'string') {
    throw new FsError('plugin ruleId is required');
  }
  if (!record.ruleId.startsWith('USER-')) {
    throw new FsError('plugin rule id must start with USER-');
  }
  const sinks = Array.isArray(record.sinks) ? record.sinks : [];
  const sanitizers = Array.isArray(record.sanitizers) ? record.sanitizers : [];
  return {
    ruleId: record.ruleId,
    sources: Array.isArray(record.sources) ? record.sources.filter((item) => typeof item === 'string') : [],
    sinks: sinks.filter((item) => asRecord(item)?.pattern !== undefined) as PluginDoc['sinks'],
    sanitizers: sanitizers.filter((item) => asRecord(item)?.pattern !== undefined) as PluginDoc['sanitizers'],
  };
}

export function runPlugin(plugin: PluginDoc, file: string, source: string, pluginPath: string): PluginFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: PluginFinding[] = [];
  const lines = source.split(/\r?\n/);
  lines.forEach((line, index) => {
    const sink = plugin.sinks.find((item) => line.includes(item.pattern));
    if (sink === undefined) {
      return;
    }
    const sanitizer = plugin.sanitizers.find((item) => source.includes(item.pattern) && item.clears.includes(sink.sinkClass));
    if (sanitizer !== undefined) {
      findings.push({
        ruleId: plugin.ruleId,
        file,
        line: index + 1,
        severity: 'high',
        message: `cleared ${sink.sinkClass}`,
        witness: { pluginPath, cleared: sink.sinkClass },
      });
      return;
    }
    findings.push({
      ruleId: plugin.ruleId,
      file,
      line: index + 1,
      severity: 'high',
      message: sink.sinkClass,
      witness: { pluginPath, cleared: null },
    });
  });
  return findings;
}
