/**
 * Phase 32 DLP leak builders. Secrets are assembled at test time so the
 * committed tree never contains a contiguous realistic-looking key (spec §14).
 */

export function awsAccessKey(): string {
  return 'AKIA' + 'TESTTESTTESTTEST';
}

export function stripeSecret(): string {
  return 'sk_test_' + 'abcdefghijklmnopqrstuvwx';
}

export function githubToken(): string {
  return 'ghp_' + 'abcdefghijklmnopqrstuvwxyz0123456789';
}

export function slackToken(): string {
  return 'xoxb-' + '1234567890-abcdefghij';
}

export function googleApiKey(): string {
  return 'AIza' + 'SyDabcdefghijklmnopqrstuvwxyz012345';
}

export function anthropicKey(): string {
  return 'sk-ant-' + 'abcdefghijklmnopqrstuvwxyz';
}

export function pemHeader(): string {
  return '-----BEGIN RSA PRIVATE KEY-----';
}

export function dbUrl(): string {
  return 'postgres://app:' + 's3cretpass' + '@10.1.2.3:5432/app';
}

export const VISA_TEST_PAN = '4111111111111111';
export const VISA_TEST_PAN_DASHED = '4111-1111-1111-1111';
export const NON_LUHN_PAN = '4111111111111112';

export const STACK_TRACE = [
  'Error: boom',
  '    at handle (/app/src/routes/user.js:42:11)',
  '    at Layer.handle (/app/node_modules/express/lib/router/layer.js:95:5)',
].join('\n');

export function leakBodies() {
  return {
    aws: { token: awsAccessKey() },
    stripe: { token: stripeSecret() },
    github: { token: githubToken() },
    slack: { token: slackToken() },
    google: { token: googleApiKey() },
    ai: { token: anthropicKey() },
    pem: { key: pemHeader() },
    db: { url: dbUrl() },
    stack: { error: STACK_TRACE },
    internalIp: { host: '10.1.2.3' },
    internalRfc1918b: { host: '192.168.10.4' },
    internalRfc1918c: { host: '172.16.0.8' },
    loopback: { host: '127.0.0.1' },
    localhost: { host: 'localhost' },
    internalDns: { host: 'redis.prod.internal' },
    card: { card: VISA_TEST_PAN },
    cardDashed: { card: VISA_TEST_PAN_DASHED },
    oneEmail: { email: 'user@example.com' },
    manyEmails: {
      users: Array.from({ length: 8 }, (_, i) => `user${String(i)}@example.com`),
    },
  };
}
