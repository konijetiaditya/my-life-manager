/** After a restore (or any load) every record must have the fields the screens rely on, with the
 *  right types. A record that is missing a required field is skipped (and counted) instead of being
 *  allowed to crash the app. Optional fields are given safe defaults. Unknown fields are dropped. */
type T = 's' | 'n' | 'd' | 'b';
interface Spec {
  req: Record<string, T>;
  opt: Record<string, T>;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const isDate = (v: unknown): v is string => {
  if (typeof v !== 'string' || !DATE.test(v)) return false;
  const [y, m, d] = v.split('-').map(Number) as [number, number, number];
  const dt = new Date(y, m - 1, d);
  return dt.getFullYear() === y && dt.getMonth() === m - 1 && dt.getDate() === d;
};

const FILE_FIELDS = ['attach_id', 'policyDoc_id', 'receipt_id', 'invoice_id', 'photo_id', 'file_id'];

export const SPECS: Record<string, Spec> = {
  bills: { req: { name: 's', amount: 'n', category: 's', dueDate: 'd', recurrence: 's' }, opt: { customDays: 'n', status: 's', paidDate: 's', notes: 's', attach: 's' } },
  ins: { req: { type: 's', provider: 's', name: 's', number: 's', coverage: 'n', premium: 'n', start: 'd', expiry: 'd', renewal: 'd' }, opt: { freq: 's', beneficiary: 's', owner: 's', policyDoc: 's', receipt: 's', notes: 's' } },
  inv: { req: { name: 's', invested: 'n' }, opt: { category: 's', platform: 's', nominee: 's', units: 'n', purchaseDate: 's', sip: 'n', sipDay: 'n', notes: 's' } },
  gold: { req: { name: 's', weight: 'n', amount: 'n', date: 'd' }, opt: { kind: 's', purity: 's', making: 'n', gst: 'n', seller: 's', invoice: 's', photo: 's', notes: 's' } },
  silver: { req: { name: 's', weight: 'n', amount: 'n', date: 'd' }, opt: { kind: 's', purity: 's', making: 'n', gst: 'n', seller: 's', invoice: 's', photo: 's', notes: 's' } },
  docs: { req: { name: 's', category: 's' }, opt: { owner: 's', issue: 's', expiry: 's', remind: 'n', description: 's', file: 's', size: 'n' } },
  rem: { req: { title: 's', date: 'd' }, opt: { time: 's', recurrence: 's', custom: 'n', advance: 'n', notes: 's', done: 'b' } },
  loans: { req: { name: 's', principal: 'n', outstanding: 'n', rate: 'n', emi: 'n', emiDay: 'n', start: 'd', end: 'd' }, opt: { kind: 's', lender: 's', notes: 's' } },
};

const ok = (t: T, v: unknown): boolean =>
  t === 's' ? typeof v === 'string' : t === 'n' ? typeof v === 'number' && Number.isFinite(v) : t === 'b' ? typeof v === 'boolean' : isDate(v);
const dflt = (t: T): string | number | boolean => (t === 'n' ? 0 : t === 'b' ? false : '');

function fixRecord(c: string, r: Record<string, unknown>): Record<string, unknown> | null {
  const spec = SPECS[c]!;
  const out: Record<string, unknown> = { id: r.id };
  for (const [k, t] of Object.entries(spec.req)) {
    if (!ok(t, r[k])) return null;
    out[k] = r[k];
  }
  for (const [k, t] of Object.entries(spec.opt)) out[k] = ok(t, r[k]) ? r[k] : dflt(t);
  if (c === 'ins' && !out.freq) out.freq = 'annual';
  if (c === 'bills') {
    out.status = out.status === 'paid' ? 'paid' : 'unpaid';
    const h = Array.isArray(r.history) ? r.history : [];
    out.history = h.filter((x): x is { date: string; amount: number } => !!x && typeof x === 'object' && isDate((x as { date?: unknown }).date) && ok('n', (x as { amount?: unknown }).amount)).map((x) => ({ date: x.date, amount: x.amount }));
  }
  if (c === 'inv') {
    const t = Array.isArray(r.txns) ? r.txns : [];
    out.txns = t
      .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && isDate((x as { date?: unknown }).date) && ok('n', (x as { amount?: unknown }).amount))
      .map((x) => ({ id: typeof x.id === 'string' ? x.id : '', date: x.date, amount: x.amount, units: ok('n', x.units) ? x.units : 0, note: typeof x.note === 'string' ? x.note : '' }));
  }
  for (const f of FILE_FIELDS) if (typeof r[f] === 'string' && /^[0-9a-f]{32}$/.test(r[f] as string)) out[f] = r[f];
  return out;
}

export function repairCollections(o: Record<string, unknown>): { dropped: number } {
  let dropped = 0;
  for (const c of Object.keys(SPECS)) {
    const arr = Array.isArray(o[c]) ? (o[c] as Array<Record<string, unknown>>) : [];
    const seen = new Set<string>();
    const kept: Array<Record<string, unknown>> = [];
    for (const r of arr) {
      const f = r && typeof r === 'object' ? fixRecord(c, r) : null;
      if (!f || seen.has(String(f.id))) {
        dropped++;
        continue;
      }
      seen.add(String(f.id));
      kept.push(f);
    }
    o[c] = kept;
  }
  return { dropped };
}
