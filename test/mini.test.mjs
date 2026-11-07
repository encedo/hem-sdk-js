// The stripped build (rollup.mini.config.js): what a project keeps is there,
// with everything it calls; what it does not keep is not; and the same input
// gives the same bytes. Needs rollup: ROLLUP=<path to the rollup binary>, or
// it skips (the SDK itself stays dependency-free).
//
//   ROLLUP=$(npm exec --yes --package=rollup@4.63.2 -- which rollup) node --test test/mini.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rollup = process.env.ROLLUP;
const skip = rollup ? false : 'ROLLUP not set';

function build(spec, name) {
  const dir = mkdtempSync(join(tmpdir(), 'hem-mini-'));
  const keep = join(dir, 'keep.json'), out = join(dir, name);
  writeFileSync(keep, JSON.stringify(spec));
  execFileSync(rollup, ['-c', 'rollup.mini.config.js', '--silent'], { cwd: root, env: { ...process.env, KEEP: keep, OUT: out } });
  return out;
}

test('a kept method is there with what it calls, and nothing else of HEM is', { skip }, async () => {
  const out = build(['ecdhHkdf', 'searchKeysAll', 'authorizePassword'], 'a.js');
  const m = await import(pathToFileURL(out).href);
  assert.deepEqual(Object.keys(m).sort(), ['HEM', 'HemError'], 'HEM and HemError unless asked otherwise');
  const h = new m.HEM('https://hem.invalid');
  for (const k of ['ecdhHkdf', 'searchKeysAll', 'authorizePassword']) assert.equal(typeof h[k], 'function', k);
  assert.equal(typeof h.searchKeys, 'function', 'searchKeysAll calls searchKeys, so it comes along');
  for (const k of ['uploadFirmware', 'exdsaSign', 'attest', 'listKeys', 'ecdh']) assert.equal(h[k], undefined, `${k} was not kept`);
  const text = readFileSync(out, 'utf8');
  assert.match(text.split('\n')[1], /#req/, 'the header lists the private methods kept with them');
  assert.ok(!text.includes('class Attest'), 'a class no kept method reaches is gone');
  assert.ok(!text.includes(root), 'no path of this machine in the output');
  await assert.rejects(h.ecdhHkdf('t', '0123456789abcdef0123456789abcdef', { items: [{}] }), (e) => e instanceof m.HemError && e.code === 'invalid_arg',
    'a kept method still validates with the helpers it needs');
});

test('the same keep list gives the same bytes, and an unknown method is an error', { skip }, () => {
  const spec = { methods: ['ecdh', 'hemCheckin'], exports: ['HEM'] };
  assert.equal(readFileSync(build(spec, 'x.js'), 'utf8'), readFileSync(build(spec, 'y.js'), 'utf8'));
  assert.throws(() => build(['noSuchMethod'], 'z.js'), /noSuchMethod/);
});
