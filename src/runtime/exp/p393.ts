/**
 * Phase 393. Local OpenTelemetry export.
 * Off unless FULLSHIELD_EXPERIMENTAL_OTELLOCAL=1.
 * There is no default endpoint. The peer is imported only when an endpoint is set.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_OTELLOCAL';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface LocalEvent {
  hook: string;
  labels: string[];
}

export interface TelemetryStart {
  imported: boolean;
  startup: string[];
}

export function startTelemetry(
  config: { endpoint?: string },
  load: (specifier: string) => void,
  send: (endpoint: string, event: LocalEvent) => void,
  event: LocalEvent | null,
): TelemetryStart {
  if (!enabled() || config.endpoint === undefined || config.endpoint === '') {
    return { imported: false, startup: [] };
  }
  const endpoint = config.endpoint;
  load('@opentelemetry/api');
  if (event !== null) {
    const payload: LocalEvent = { hook: event.hook, labels: [...event.labels] };
    send(endpoint, payload);
  }
  return { imported: true, startup: [`telemetry endpoint ${endpoint}`] };
}
