import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { FLAG, scanTerraform, TF_ACL, TF_CIDR, TF_USERDATA } from '../../../src/phases/p456.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const token = `AKIA${'Z'.repeat(16)}`;
const text = `
resource "aws_security_group" "app" {
  ingress {
    from_port = 3000
    to_port = 3000
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "other" {
  ingress {
    from_port = 3000
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "web" {
  vpc_security_group_ids = [aws_security_group.app.id]
  user_data = "${token}"
  tags = { Name = "demo-app" }
}
resource "aws_s3_bucket_acl" "state" {
  bucket = aws_s3_bucket.state.id
  acl = "public-read"
}
`;

describe('phase 456', () => {
  it('reports the app CIDR, the public-read bucket, and the user_data token', () => {
    process.env[FLAG] = '1';
    const linked = `${text}\nresource "aws_instance" "stateful" {\n  user_data = "state=\${aws_s3_bucket.state.bucket} demo-app"\n}\n`;
    const result = scanTerraform('main.tf', linked, 'demo-app');
    expect(result.findings.some((row) => row.ruleId === TF_CIDR)).toBe(true);
    expect(result.findings.some((row) => row.ruleId === TF_ACL)).toBe(true);
    expect(result.findings.some((row) => row.ruleId === TF_USERDATA)).toBe(true);
    expect(JSON.stringify(result.findings)).not.toContain(token);
  });

  it('omits a CIDR on an unconnected group', () => {
    process.env[FLAG] = '1';
    const result = scanTerraform('main.tf', text, 'demo-app');
    const cidr = result.findings.filter((row) => row.ruleId === TF_CIDR);
    expect(cidr.every((row) => row.message.includes('0.0.0.0/0'))).toBe(true);
    expect(cidr).toHaveLength(1);
  });

  it('records a subset event and stays quiet when the flag is off', () => {
    process.env[FLAG] = '1';
    const result = scanTerraform('main.tf', 'module "x" "y" {\n  source = "./mod"\n}\n', 'demo-app');
    expect(result.events.length).toBeGreaterThan(0);
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'main.tf', line: 1, message: 'kept' }];
    delete process.env[FLAG];
    expect(scanTerraform('main.tf', text, 'demo-app', baseline).findings).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p456.ts'), 'utf8');
    expect(src.includes('node:http')).toBe(false);
  });
});
