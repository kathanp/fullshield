const CAPABILITY_NAMES = [
  'child_process',
  'net',
  'fs_write',
  'env',
  'eval',
  'native',
  'dynamic_require',
  'install_script',
  'obfuscation',
] as const;

export type CapabilityName = (typeof CAPABILITY_NAMES)[number];

export function isCapabilityName(value: string): value is CapabilityName {
  return (CAPABILITY_NAMES as readonly string[]).includes(value);
}
