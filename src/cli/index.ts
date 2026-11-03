#!/usr/bin/env node
import { applyFlagGroups } from '../core/flag-groups.js';
import { createProgram } from './program.js';

applyFlagGroups();
await createProgram().parseAsync(process.argv);
