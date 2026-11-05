#!/usr/bin/env node
import { applyFlagGroups } from '../core/flag-groups.js';
import { nodeFloorMessage } from './node-floor.js';
import { createProgram } from './program.js';

const floor = nodeFloorMessage(process.versions.node);
if (floor !== undefined) {
  process.stderr.write(`${floor}\n`);
  process.exit(1);
}

applyFlagGroups();
await createProgram().parseAsync(process.argv);
