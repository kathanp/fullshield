/** Phase 30 history / bundle / verify-secrets. Off unless the env flag is set. */
export function secretsAdvEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_SECRETS_ADV === '1';
}

/** Phase 105 committed credential files. Off unless the env flag is set. */
export function credFilesEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_CREDFILES === '1';
}
