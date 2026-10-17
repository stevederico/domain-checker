#!/usr/bin/env node
/**
 * Hunt for short available domains that are easy to spell.
 *
 * Names are generated on this machine, then checked one at a time through the
 * Domain Checker API with a `tlds` filter. Nothing else sees the names.
 *
 *   npm run hunt -- --count 200
 *   npm run hunt -- --source words
 *   npm run hunt -- --seeds agent,nova --len 4-6
 *
 * Every result is appended to a local cache so a name is never sent twice.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * Consonants with one obvious spelling. No c/k/q (sound alike), no h/j/w/y
 * (vowel-ish or ambiguous). `g` is hard only before a/o/u, so it is limited there.
 */
const CONSONANTS = 'bdfglmnprtv'.split('');
/** Extra name openers that are only unambiguous at the start (s/z sound alike mid-word). */
const START_ONLY = ['s', 'z'];
/** Two-letter openers people spell right on the first try. */
const ONSET_CLUSTERS = ['bl', 'br', 'dr', 'fl', 'fr', 'gl', 'gr', 'pl', 'pr', 'sl', 'sp', 'st', 'tr'];
/** Mid-word clusters that split cleanly into syllables ("nol-ta", "tam-ba"). */
const MEDIAL_CLUSTERS = ['nd', 'nt', 'mb', 'lt', 'ld', 'rd', 'rt', 'rn', 'lv', 'rv', 'st', 'lm', 'rm'];
const VOWELS = 'aeiou'.split('');
/** Final vowels with one spelling. A final e reads as silent, and i/u invite y/oo. */
const END_VOWELS = ['a', 'o'];
/** Final consonants with one spelling. */
const END_CONSONANTS = ['n', 'r', 'l', 'x'];
/** Endings blended onto seed words. */
const SUFFIXES = ['a', 'o', 'io', 'ix', 'ly', 'er', 'on', 'ra', 'us', 'an'];
/** Default word list for `--source words`: ships with cracklib on Arch, has words and first names. */
const DEFAULT_WORDS = '/usr/share/dict/cracklib-small';
/** Spacing between API calls. The server allows 30 per minute per IP. */
const REQUEST_GAP_MS = 2100;
/** Wait after a 429. The server window is 60 seconds. */
const RATE_LIMIT_WAIT_MS = 61_000;
/** First 5xx/network backoff, doubled on each retry. */
const BACKOFF_BASE_MS = 2000;
const MAX_RETRIES = 3;
/** Stop the run after this many names fail in a row. */
const CIRCUIT_BREAKER = 3;

const DEFAULTS = {
  api: 'https://checker.bixbyapps.com/api/check',
  cache: join(homedir(), '.cache', 'domain-checker', 'hunt.jsonl'),
  count: 100,
  minLen: 4,
  maxLen: 5,
  require: 'any',
  seeds: [],
  source: 'invented',
  words: DEFAULT_WORDS,
  tlds: ['com', 'ai'],
  dryRun: false,
};

const pick = (arr, rand) => arr[Math.floor(rand() * arr.length)];
const isVowel = (ch) => VOWELS.includes(ch);

/** Consonant that reads one way before `next` (hard g only before a/o/u). */
const consonantBefore = (vowel, rand) => {
  const pool = 'aou'.includes(vowel) ? CONSONANTS : CONSONANTS.filter((c) => c !== 'g');
  return pick(pool, rand);
};

/**
 * Build one invented name that is spelled the way it sounds.
 *
 * Shape: optional opener (vowel, cluster, or s/z), consonant+vowel syllables,
 * at most one clean medial cluster, and a final a/o or n/r/l/x.
 *
 * @param {number} len - Exact target length, 4 or more.
 * @param {() => number} rand - Random source returning [0, 1).
 * @returns {string} A name of `len` letters.
 */
export function spellableName(len, rand = Math.random) {
  const roll = rand();
  let s = '';
  if (roll < 0.15) s = pick(['a', 'o'], rand);
  else if (roll < 0.35 && len >= 5) s = pick(ONSET_CLUSTERS, rand);
  else if (roll < 0.5) s = pick(START_ONLY, rand);
  let hasCluster = s.length === 2;
  while (s.length < len) {
    const left = len - s.length;
    const last = s.at(-1);
    if (left === 1) {
      s += last && isVowel(last) ? pick(END_CONSONANTS, rand) : pick(END_VOWELS, rand);
    } else if (!last || isVowel(last)) {
      // Spend the one cluster mid-word only when a vowel can still follow it.
      if (last && !hasCluster && left >= 3 && rand() < 0.3) {
        s += pick(MEDIAL_CLUSTERS, rand);
        hasCluster = true;
      } else {
        const v = left === 2 ? pick(END_VOWELS, rand) : pick(VOWELS, rand);
        s += consonantBefore(v, rand) + v;
      }
    } else {
      s += left === 2 ? pick(END_VOWELS, rand) : pick(VOWELS, rand);
    }
  }
  return s;
}

/**
 * Blend seed words with short endings, plus shorter stems of long seeds.
 *
 * @param {string[]} seeds - Root words, any case.
 * @param {number} minLen - Shortest name to keep.
 * @param {number} maxLen - Longest name to keep.
 * @returns {string[]} Unique blends within the length range.
 */
export function seedNames(seeds, minLen, maxLen) {
  const out = new Set();
  for (const raw of seeds) {
    const seed = raw.toLowerCase().replace(/[^a-z0-9]/g, '');
    // Shorter stems let long seeds still produce short names ("agent" -> "agen", "age").
    const stems = [seed, ...Array.from({ length: Math.max(0, seed.length - 3) }, (_, i) => seed.slice(0, seed.length - 1 - i))];
    for (const stem of stems.filter((st) => st.length >= 3)) {
      out.add(stem);
      for (const suf of SUFFIXES) {
        // Swap the stem's last vowel for the suffix's ("nova" + "io" -> "novio", not "novaio").
        out.add(isVowel(stem.at(-1)) && isVowel(suf[0]) ? stem.slice(0, -1) + suf : stem + suf);
      }
    }
  }
  return [...out].filter((n) => n.length >= minLen && n.length <= maxLen);
}

/**
 * Load single words from a newline-separated list.
 *
 * @param {string} path - Word list file.
 * @param {number} minLen - Shortest word to keep.
 * @param {number} maxLen - Longest word to keep.
 * @returns {string[]} Lowercase a-z words, deduped.
 * @throws {Error} When the file is missing.
 */
export function loadWords(path, minLen, maxLen) {
  if (!existsSync(path)) throw new Error(`Word list not found: ${path}. Pass --words <file>.`);
  const words = readFileSync(path, 'utf8')
    .split('\n')
    .map((w) => w.trim().toLowerCase())
    .filter((w) => /^[a-z]+$/.test(w) && w.length >= minLen && w.length <= maxLen);
  return [...new Set(words)];
}

/**
 * Fisher-Yates shuffle into a new array.
 *
 * @param {string[]} arr - Items to shuffle.
 * @param {() => number} rand - Random source returning [0, 1).
 * @returns {string[]} Shuffled copy.
 */
export function shuffle(arr, rand = Math.random) {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * Produce up to `count` fresh candidate names.
 *
 * Seed blends come first. Then either shuffled list words (`source: words`)
 * or invented spellable names (`source: invented`) fill the rest.
 *
 * @param {object} opts - Same shape as `DEFAULTS`.
 * @param {Set<string>} skip - Names already checked.
 * @param {() => number} rand - Random source returning [0, 1).
 * @returns {string[]} Candidates not in `skip`.
 */
export function generateNames(opts, skip = new Set(), rand = Math.random) {
  const out = new Set();
  const add = (n) => out.size < opts.count && !skip.has(n) && out.add(n);
  seedNames(opts.seeds, opts.minLen, opts.maxLen).forEach(add);
  if (opts.source === 'words') {
    shuffle(loadWords(opts.words, opts.minLen, opts.maxLen), rand).forEach(add);
    return [...out];
  }
  // Invented names can collide with the cache, so cap attempts instead of looping forever.
  for (let tries = 0; out.size < opts.count && tries < opts.count * 50; tries++) {
    add(spellableName(opts.minLen + Math.floor(rand() * (opts.maxLen - opts.minLen + 1)), rand));
  }
  return [...out];
}

/**
 * Parse CLI flags into options.
 *
 * @param {string[]} argv - Arguments after the script path.
 * @returns {object} Options merged over `DEFAULTS`.
 * @throws {Error} On an unknown flag or bad value.
 */
export function parseArgs(argv) {
  const opts = { ...DEFAULTS };
  const list = (v) => v.split(',').map((s) => s.trim().replace(/^\./, '')).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--dry-run') {
      opts.dryRun = true;
      continue;
    }
    const v = argv[++i];
    if (v === undefined) throw new Error(`${flag} needs a value`);
    if (flag === '--count') opts.count = Number(v);
    else if (flag === '--len') [opts.minLen, opts.maxLen = opts.minLen] = v.split('-').map(Number);
    else if (flag === '--tlds') opts.tlds = list(v);
    else if (flag === '--seeds') opts.seeds = list(v);
    else if (['--require', '--source', '--words', '--api', '--cache'].includes(flag)) opts[flag.slice(2)] = v;
    else throw new Error(`Unknown flag ${flag}`);
  }
  if (!(opts.count > 0)) throw new Error('--count must be a positive number');
  if (!(opts.minLen >= 1 && opts.maxLen <= 63 && opts.minLen <= opts.maxLen)) throw new Error('--len must look like 4-5');
  if (!['all', 'any'].includes(opts.require)) throw new Error('--require must be all or any');
  if (!['invented', 'words'].includes(opts.source)) throw new Error('--source must be invented or words');
  return opts;
}

/**
 * Read names already checked from the JSONL cache.
 *
 * @param {string} path - Cache file.
 * @returns {Set<string>} Cached names. Empty when the file is missing.
 */
export function readCache(path) {
  if (!existsSync(path)) return new Set();
  const names = new Set();
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line) continue;
    try {
      names.add(JSON.parse(line).name);
    } catch {
      console.error(`skipping bad cache line: ${line.slice(0, 40)}`);
    }
  }
  return names;
}

/**
 * Decide whether a result row is a hit.
 *
 * @param {Record<string, string>} statuses - TLD to status from the API.
 * @param {string[]} tlds - TLDs that were requested.
 * @param {'all'|'any'} require - Every TLD free, or at least one.
 * @returns {boolean} True when the row meets `require`.
 */
export function isHit(statuses, tlds, require) {
  const free = tlds.map((t) => statuses[t] === 'available');
  return require === 'all' ? free.every(Boolean) : free.some(Boolean);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Check one name through the Domain Checker API.
 *
 * Retries up to `MAX_RETRIES` times: 61s after a 429, exponential backoff
 * after a 5xx or network error. Other 4xx responses fail at once.
 *
 * @param {string} name - Base label.
 * @param {object} opts - Needs `api` and `tlds`.
 * @returns {Promise<Record<string, string>>} TLD to status.
 * @throws {Error} When every attempt fails or the API rejects the request.
 */
export async function checkName(name, opts, wait = sleep) {
  let lastError = 'no attempts';
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) await wait(lastError.startsWith('429') ? RATE_LIMIT_WAIT_MS : BACKOFF_BASE_MS * 2 ** (attempt - 1));
    let res;
    try {
      res = await fetch(opts.api, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'domain-checker-hunt' },
        body: JSON.stringify({ domain: name, tlds: opts.tlds }),
      });
    } catch (err) {
      lastError = `network: ${err.message}`;
      continue;
    }
    if (res.ok) return Object.fromEntries((await res.json()).map((r) => [r.tld, r.status]));
    lastError = `${res.status} ${await res.text()}`;
    if (res.status !== 429 && res.status < 500) break;
    console.error(`${name}: ${lastError}, retrying`);
  }
  throw new Error(lastError);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const names = generateNames(opts, readCache(opts.cache));
  if (opts.dryRun) return console.log(names.join('\n'));
  mkdirSync(dirname(opts.cache), { recursive: true });
  const mins = Math.ceil((names.length * REQUEST_GAP_MS) / 60_000);
  console.error(`checking ${names.length} names on .${opts.tlds.join(', .')} (~${mins} min) via ${opts.api}`);
  let hits = 0;
  let failuresInRow = 0;
  for (const [i, name] of names.entries()) {
    if (i > 0) await sleep(REQUEST_GAP_MS);
    let statuses;
    try {
      statuses = await checkName(name, opts);
      failuresInRow = 0;
    } catch (err) {
      console.error(`${name}: ${err.message}`);
      if (++failuresInRow >= CIRCUIT_BREAKER) throw new Error(`stopping: ${CIRCUIT_BREAKER} names failed in a row`);
      continue;
    }
    appendFileSync(opts.cache, `${JSON.stringify({ name, ...statuses, at: new Date().toISOString() })}\n`);
    if (!isHit(statuses, opts.tlds, opts.require)) continue;
    hits++;
    console.log(`${name}\t${opts.tlds.filter((t) => statuses[t] === 'available').map((t) => `${name}.${t}`).join(' ')}`);
  }
  console.error(`done: ${hits} hits of ${names.length}. cache: ${opts.cache}`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
