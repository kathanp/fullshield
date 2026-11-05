const MIN_NODE = [22, 13, 0] as const;

/** Undefined when this Node can load the CLI. Otherwise a message for stderr. */
export function nodeFloorMessage(version: string): string | undefined {
  const parts = version.split('.').map((part) => Number(part));
  for (let i = 0; i < MIN_NODE.length; i += 1) {
    const got = parts[i] ?? 0;
    const need = MIN_NODE[i] ?? 0;
    if (Number.isNaN(got) || got < need) {
      return `fullshield requires Node 22.13 or newer (current ${version})`;
    }
    if (got > need) {return undefined;}
  }
  return undefined;
}
