/** Defensive cleaning of data that comes from outside (a restored backup). */
const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_STR = 5000;
const MAX_ARR = 50000;
const MAX_DEPTH = 8;

export const COLLECTIONS = ['bills', 'ins', 'inv', 'gold', 'silver', 'docs', 'rem', 'loans'] as const;

export function sanitize(v: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new Error('Data is nested too deeply');
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('Invalid number');
    return v;
  }
  if (typeof v === 'string') return v.length > MAX_STR ? v.slice(0, MAX_STR) : v;
  if (Array.isArray(v)) {
    if (v.length > MAX_ARR) throw new Error('Too many records');
    return v.map((x) => sanitize(x, depth + 1));
  }
  if (typeof v === 'object') {
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (BAD_KEYS.has(k)) continue;
      out[k] = sanitize(val, depth + 1);
    }
    return Object.assign({}, out);
  }
  throw new Error('Unsupported value');
}

export interface ParsedState {
  settings: Record<string, unknown>;
  activity: unknown[];
  [k: string]: unknown;
}

/** Parses and checks a state document. Throws a readable Error when it is not usable. */
export function parseState(json: string): ParsedState {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new Error('The data is not valid.');
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('The data is not valid.');
  const o = sanitize(raw) as Record<string, unknown>;
  for (const c of COLLECTIONS) {
    const arr = o[c];
    if (arr === undefined) {
      o[c] = [];
      continue;
    }
    if (!Array.isArray(arr)) throw new Error(`The "${c}" section is not valid.`);
    for (const item of arr) {
      if (!item || typeof item !== 'object' || Array.isArray(item) || !/^[A-Za-z0-9_-]{1,40}$/.test(String((item as { id?: unknown }).id ?? '')) || typeof (item as { id?: unknown }).id !== 'string') {
        throw new Error(`A record in "${c}" is not valid.`);
      }
    }
  }
  if (!o.settings || typeof o.settings !== 'object' || Array.isArray(o.settings)) o.settings = {};
  if (!Array.isArray(o.activity)) o.activity = [];
  return o as ParsedState;
}
