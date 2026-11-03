import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const RULE = `# FullShield agent guardrail

Before committing, run FullShield on the working diff.

- Use the MCP tools \`check_diff\` and \`get_findings\`.
- \`verified_fix\` writes a temp copy only. It does not change this tree.
- A finding on a line outside the working diff does not block the commit.
`;

export async function writeAgentConfig(cwd: string, agent: string): Promise<string[]> {
  if (agent !== 'cursor' && agent !== 'claude') {
    throw new Error('init --agent expects cursor or claude');
  }
  const written: string[] = [];
  if (agent === 'cursor') {
    const rules = join(cwd, '.cursor', 'rules');
    await mkdir(rules, { recursive: true });
    await writeFile(join(rules, 'fullshield.mdc'), RULE, 'utf8');
    await writeFile(
      join(cwd, '.cursor', 'mcp.json'),
      `${JSON.stringify({ mcpServers: { fullshield: { command: 'fullshield', args: ['mcp', '--stdio'] } } }, null, 2)}\n`,
      'utf8',
    );
    written.push('.cursor/rules/fullshield.mdc', '.cursor/mcp.json');
  } else {
    await writeFile(join(cwd, 'CLAUDE.md'), RULE, 'utf8');
    await writeFile(
      join(cwd, '.mcp.json'),
      `${JSON.stringify({ mcpServers: { fullshield: { command: 'fullshield', args: ['mcp', '--stdio'] } } }, null, 2)}\n`,
      'utf8',
    );
    written.push('CLAUDE.md', '.mcp.json');
  }
  return written;
}
