/** Raise a scan error by message so the CLI can map it to a code. */
export function raise(message: string): never {
  const error = new Error(message);
  throw error;
}
