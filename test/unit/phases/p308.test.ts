import { afterEach, describe, expect, it } from 'vitest';

import { analyzeFastifyScope, enabled, FLAG } from '../../../src/phases/p308.js';

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 308 fastify scope', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    expect(analyzeFastifyScope("fastify.get('/b', handler);").routes).toEqual([]);
  });

  it('keeps a child hook off a sibling unless the plugin breaks scope', () => {
    process.env[FLAG] = '1';
    const child = analyzeFastifyScope('function child(f, opts, done) { f.addHook("preHandler", auth); f.get("/a", handler); done(); }\nfastify.register(child);\nfastify.get("/b", handler);');
    expect(child.routes.find((route) => route.path === '/a')?.covered).toBe(true);
    expect(child.routes.find((route) => route.path === '/b')?.covered).toBe(false);
    const broken = analyzeFastifyScope('function plugin(f, opts, done) { f.addHook("preHandler", auth); done(); }\nfastify.register(fp(plugin));\nfastify.get("/b", handler);');
    expect(broken.routes.find((route) => route.path === '/b')?.covered).toBe(true);
  });

  it('does not let a child decorator override the parent route', () => {
    process.env[FLAG] = '1';
    const result = analyzeFastifyScope('fastify.decorate("user", parentUser);\nfastify.get("/p", handler);\nfastify.register((f, opts, done) => { f.decorate("user", childUser); f.get("/c", handler); done(); });');
    expect(result.routes.find((route) => route.path === '/p')?.decorator).toBe('parentUser');
    expect(result.routes.find((route) => route.path === '/c')?.decorator).toBe('childUser');
    const dynamic = analyzeFastifyScope('fastify.register(flag ? fp(plugin) : plugin);');
    expect(dynamic.events.map((event) => event.reason)).toContain('computed fastify-plugin');
  });
});
