/**
 * Phase 451. Dockerfile stage graph.
 * Off unless FULLSHIELD_EXPERIMENTAL_DOCKERFILE=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Does not invoke a container tool. A parser failure is an event, not a clean result.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DOCKERFILE';

export const DOCKER_USER = 'CONFIG-DOCKER-USER-001';
export const DOCKER_ENV_COPY = 'CONFIG-DOCKER-ENVFILE-001';
export const DOCKER_NPM = 'CONFIG-DOCKER-NPM-001';
const DOCKER_ARG = 'CONFIG-DOCKER-ARG-001';
const DOCKER_ROOT_STAGE = 'CONFIG-DOCKER-ROOT-STAGE-001';

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
}

export interface PhaseEvent {
  kind: 'parser-failure';
  file: string;
  line: number;
  reason: string;
}

export interface PhaseResult {
  findings: PhaseFinding[];
  events: PhaseEvent[];
  clean: boolean;
}

interface Stage {
  name: string;
  line: number;
  user: string | null;
  copiesFrom: string[];
  hasManifest: boolean;
  npmInstallLine: number | null;
  npmCi: boolean;
  envCopyLine: number | null;
  secretArgLine: number | null;
}

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;

function unclosed(line: string): boolean {
  const quotes = line.match(/"/g);
  return quotes !== null && quotes.length % 2 === 1;
}

function emptyResult(baseline: readonly PhaseFinding[]): PhaseResult {
  return { findings: [...baseline], events: [], clean: true };
}

function stageName(line: string, index: number): string {
  const named = /\bAS\s+(\S+)/i.exec(line);
  return named?.[1] ?? `stage-${index}`;
}

function note(stage: Stage, line: string, lineNo: number): void {
  if (/^USER\s+/i.test(line)) {
    stage.user = line.replace(/^USER\s+/i, '').trim();
  }
  const from = /^COPY\s+--from=(\S+)/i.exec(line);
  if (from?.[1] !== undefined) {
    stage.copiesFrom.push(from[1]);
  }
  if (/package-lock\.json|package\.json/.test(line) && /^COPY\s+/i.test(line)) {
    stage.hasManifest = true;
  }
  if (/^RUN\s+/.test(line) && /\bnpm\s+install\b/.test(line)) {
    stage.npmInstallLine = lineNo;
  }
  if (/^RUN\s+/.test(line) && /\bnpm\s+ci\b/.test(line)) {
    stage.npmCi = true;
  }
  if (/^COPY\s+.*\s\.env(?:\s|$)/.test(line) || /^COPY\s+\.env\s/.test(line)) {
    stage.envCopyLine = lineNo;
  }
  if (/^ARG\s+/.test(line) && SECRET.test(line)) {
    stage.secretArgLine = lineNo;
  }
}

function parseStages(text: string, file: string): { stages: Stage[]; events: PhaseEvent[] } {
  const stages: Stage[] = [];
  const events: PhaseEvent[] = [];
  let current: Stage | null = null;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i] ?? '';
    const line = raw.trim();
    if (unclosed(line)) {
      events.push({ kind: 'parser-failure', file, line: i + 1, reason: 'unclosed quote' });
      return { stages: [], events };
    }
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    if (/^FROM\s+/i.test(line)) {
      current = {
        name: stageName(line, stages.length),
        line: i + 1,
        user: null,
        copiesFrom: [],
        hasManifest: false,
        npmInstallLine: null,
        npmCi: false,
        envCopyLine: null,
        secretArgLine: null,
      };
      stages.push(current);
      continue;
    }
    if (current !== null) {
      note(current, line, i + 1);
    }
  }
  return { stages, events };
}

function copiedForward(stages: readonly Stage[], name: string, index: number): boolean {
  return stages.slice(index + 1).some((stage) => stage.copiesFrom.includes(name));
}

function isRoot(user: string | null): boolean {
  return user === null || user === 'root' || user === '0';
}

function analyze(stages: readonly Stage[], file: string): PhaseFinding[] {
  const findings: PhaseFinding[] = [];
  const skipArg = process.env.FULLSHIELD_EXPERIMENTAL_DOCKERARG === '1';
  stages.forEach((stage, index) => {
    const finalStage = index === stages.length - 1;
    if (finalStage && isRoot(stage.user)) {
      findings.push({ ruleId: DOCKER_USER, severity: 'medium', file, line: stage.line, message: 'final stage has no non-root USER' });
    }
    if (!finalStage && isRoot(stage.user) && !copiedForward(stages, stage.name, index)) {
      findings.push({ ruleId: DOCKER_ROOT_STAGE, severity: 'info', file, line: stage.line, message: 'intermediate root stage is not copied forward' });
    }
    if (stage.envCopyLine !== null) {
      findings.push({ ruleId: DOCKER_ENV_COPY, severity: 'high', file, line: stage.envCopyLine, message: 'COPY of .env' });
    }
    if (stage.npmInstallLine !== null && stage.hasManifest && !stage.npmCi) {
      findings.push({ ruleId: DOCKER_NPM, severity: 'medium', file, line: stage.npmInstallLine, message: 'npm install where npm ci could run' });
    }
    const reaches = stage.secretArgLine !== null && (finalStage || copiedForward(stages, stage.name, index));
    if (reaches && !skipArg && stage.secretArgLine !== null) {
      findings.push({ ruleId: DOCKER_ARG, severity: 'high', file, line: stage.secretArgLine, message: 'secret ARG reaches the final stage' });
    }
  });
  return findings;
}

export function scanDockerfile(file: string, text: string, baseline: readonly PhaseFinding[] = []): PhaseResult {
  if (!enabled()) {
    return emptyResult(baseline);
  }
  const parsed = parseStages(text, file);
  if (parsed.events.length > 0) {
    return { findings: [...baseline], events: parsed.events, clean: false };
  }
  return { findings: [...baseline, ...analyze(parsed.stages, file)], events: [], clean: true };
}
