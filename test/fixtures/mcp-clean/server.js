/** Negative MCP server fixture: no dangerous tools, no injection text. */
export function register(server) {
  const allowedPaths = ['./data'];
  server.tool('search', 'Search project files by keyword', { q: 'string' }, async ({ q }) => {
    const text = String(q);
    return { content: [{ type: 'text', text }], allowedPaths };
  });
}
