import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkName, generateNames, isHit, loadWords, parseArgs, readCache, seedNames, spellableName } from './hunt.mjs';

/** Deterministic PRNG so generated names are stable across runs. */
const seeded = (seed) => () => {
  seed = (seed * 1103515245 + 12345) % 2 ** 31;
  return seed / 2 ** 31;
};

/** Writes `body` to a fresh temp file and returns its path. */
const tempFile = (body) => {
  const dir = mkdtempSync(join(tmpdir(), 'hunt-'));
  const path = join(dir, 'f.txt');
  writeFileSync(path, body);
  return path;
};

describe('spellableName', () => {
  const names = Array.from({ length: 300 }, (_, i) => spellableName(4 + (i % 2), seeded(i + 1)));

  it('hits the exact length', () => {
    assert.ok(names.every((n, i) => n.length === 4 + (i % 2)));
  });

  it('avoids letters with more than one spelling', () => {
    assert.ok(names.every((n) => !/[cqkhjwy]/.test(n)), names.find((n) => /[cqkhjwy]/.test(n)));
  });

  it('ends in a, o, n, r, l, or x', () => {
    assert.ok(names.every((n) => /[aonrlx]$/.test(n)), names.find((n) => !/[aonrlx]$/.test(n)));
  });

  it('only opens with a vowel when it is a or o', () => {
    assert.ok(names.every((n) => !/^[eiu]/.test(n)), names.find((n) => /^[eiu]/.test(n)));
  });
});

describe('seedNames', () => {
  it('swaps a seam vowel instead of doubling it', () => {
    const names = seedNames(['Nova'], 4, 5);
    assert.ok(names.includes('novio'));
    assert.ok(!names.some((n) => n.startsWith('novao') || n.startsWith('novai')));
  });

  it('keeps blends inside the length range', () => {
    assert.ok(seedNames(['agent'], 4, 5).every((n) => n.length >= 4 && n.length <= 5));
  });
});

describe('loadWords', () => {
  it('keeps lowercase a-z words in range, deduped', () => {
    const path = tempFile('Luna\nluna\nsky\nrocket\nx-ray\nnova\n');
    assert.deepEqual(loadWords(path, 4, 5), ['luna', 'nova']);
  });

  it('throws a clear error for a missing list', () => {
    assert.throws(() => loadWords('/no/such/list', 4, 5), /Word list not found/);
  });
});

describe('generateNames', () => {
  it('skips cached names and fills the count', () => {
    const opts = parseArgs(['--count', '30', '--seeds', 'nova']);
    const names = generateNames(opts, new Set(['nova']), seeded(7));
    assert.equal(names.length, 30);
    assert.ok(!names.includes('nova'));
  });

  it('draws from the word list for source words', () => {
    const path = tempFile('luna\nnova\nmoon\n');
    const opts = parseArgs(['--source', 'words', '--words', path, '--count', '5']);
    assert.deepEqual(generateNames(opts, new Set(['moon']), seeded(3)).sort(), ['luna', 'nova']);
  });
});

describe('parseArgs', () => {
  it('reads flags', () => {
    const opts = parseArgs(['--len', '3-4', '--tlds', '.com,ai', '--require', 'any', '--dry-run']);
    assert.deepEqual([opts.minLen, opts.maxLen, opts.tlds, opts.require, opts.dryRun], [3, 4, ['com', 'ai'], 'any', true]);
  });

  it('rejects junk', () => {
    for (const bad of [['--bogus', '1'], ['--len', '6-4'], ['--require', 'most'], ['--source', 'web'], ['--count']]) {
      assert.throws(() => parseArgs(bad));
    }
  });
});

describe('readCache', () => {
  it('returns names and skips partial lines', () => {
    const path = tempFile('{"name":"luna","com":"taken"}\n{"name":"no\n');
    assert.deepEqual([...readCache(path)], ['luna']);
  });
});

describe('isHit', () => {
  const row = { com: 'available', ai: 'taken' };

  it('needs every TLD for all', () => {
    assert.equal(isHit(row, ['com', 'ai'], 'all'), false);
  });

  it('needs one TLD for any', () => {
    assert.equal(isHit(row, ['com', 'ai'], 'any'), true);
  });
});

describe('checkName', () => {
  const realFetch = globalThis.fetch;
  const opts = { api: 'http://test/api/check', tlds: ['com', 'ai'] };
  const reply = (status, body) => new Response(JSON.stringify(body), { status });

  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('waits out a 429 and returns statuses', async () => {
    const replies = [reply(429, { error: 'slow' }), reply(200, [{ tld: 'com', status: 'available' }])];
    const waits = [];
    globalThis.fetch = async () => replies.shift();
    assert.deepEqual(await checkName('luna', opts, async (ms) => waits.push(ms)), { com: 'available' });
    assert.deepEqual(waits, [61_000]);
  });

  it('fails at once on a 400', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls++;
      return reply(400, { error: 'bad' });
    };
    await assert.rejects(checkName('luna', opts, async () => {}), /^Error: 400/);
    assert.equal(calls, 1);
  });

  it('backs off exponentially on 5xx, then gives up', async () => {
    const waits = [];
    globalThis.fetch = async () => reply(503, {});
    await assert.rejects(checkName('luna', opts, async (ms) => waits.push(ms)), /503/);
    assert.deepEqual(waits, [2000, 4000, 8000]);
  });
});
