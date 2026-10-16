export function githubOidcToken(
  env: Record<string, string | undefined>,
  fetchImpl?: (
    url: URL,
    init: { headers: Record<string, string> },
  ) => Promise<{ ok: boolean; status: number; json: () => Promise<{ value?: string } | null> }>,
): Promise<string>;
