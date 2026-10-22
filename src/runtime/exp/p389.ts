/**
 * Phase 389. Template source as the template.
 * Off unless FULLSHIELD_EXPERIMENTAL_TPLSRC=1.
 * Escaping data does not make attacker-controlled template source safe.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_TPLSRC';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const TEMPLATE_ARGUMENT: Record<string, number> = {
  'ejs.render': 0,
  'pug.render': 0,
  'handlebars.compile': 0,
  'ejs.renderFile': -1,
  'pug.renderFile': -1,
};

export interface TemplateFinding {
  ruleId: 'SAST-SSTI-001';
  argumentIndex: number;
  message: string;
}

export function templateFinding(callee: string, origin: 'request' | 'file' | 'constant'): TemplateFinding | null {
  if (!enabled()) {
    return null;
  }
  const index = TEMPLATE_ARGUMENT[callee];
  if (index === undefined || index < 0 || origin !== 'request') {
    return null;
  }
  return {
    ruleId: 'SAST-SSTI-001',
    argumentIndex: index,
    message: `Template source argument ${index} is request origin.`,
  };
}

export function templateRuntime(callee: string, labeledRequest: boolean): { event: boolean } {
  if (!enabled()) {
    return { event: false };
  }
  const index = TEMPLATE_ARGUMENT[callee];
  if (index === undefined || index < 0) {
    return { event: false };
  }
  return { event: labeledRequest };
}
