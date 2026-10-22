/** Phase 410. Context-correct escaping. Off unless FULLSHIELD_EXPERIMENTAL_CTXESCAPE=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CTXESCAPE';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function escapeEdit(
  context: 'text' | 'url' | 'script',
  alreadyWrapped: boolean,
): { edit: string | null; diff: string } {
  if (!enabled() || alreadyWrapped) {
    return { edit: null, diff: '' };
  }
  if (context === 'text') {
    return { edit: 'escapeHtml(x)', diff: '+escapeHtml(x)' };
  }
  return { edit: null, diff: '' };
}
