/** Phase 417. Helmet and CORS config edit. Off unless FULLSHIELD_EXPERIMENTAL_HELMETFIX=1. */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HELMETFIX';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function helmetFix(input: {
  express: boolean;
  helmet: boolean;
  reflect: boolean;
  foreignScript: boolean;
  apply: boolean;
}): { dryRun: string; applied: boolean; disposition: 'review'; insertedOriginTrue: boolean } {
  const empty = { dryRun: '', applied: false, disposition: 'review' as const, insertedOriginTrue: false };
  if (!enabled() || !input.express) {
    return empty;
  }
  const helmet = input.helmet ? '' : 'app.use(helmet())';
  if (input.reflect) {
    return { dryRun: `${helmet}\norigin reflect refused`.trim(), applied: false, disposition: 'review', insertedOriginTrue: false };
  }
  if (input.foreignScript) {
    return { dryRun: helmet, applied: false, disposition: 'review', insertedOriginTrue: false };
  }
  const body = helmet.length > 0 ? helmet : 'origin: false';
  return { dryRun: body, applied: input.apply, disposition: 'review', insertedOriginTrue: false };
}
