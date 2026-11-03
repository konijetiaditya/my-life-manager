import { describe, expect, it } from 'vitest';
import { repairCollections } from '../src/security/repair';

describe('repairCollections', () => {
  it('keeps good records, drops broken ones, never throws', () => {
    const o: Record<string, unknown> = {
      bills: [
        { id: 'a1', name: 'Rent', amount: 100, category: 'x', dueDate: '2026-01-31', recurrence: 'monthly', history: [{ date: '2026-01-01', amount: 5 }, { date: 'bad' }], evil: '<script>' },
        { id: 'a2', name: 'No date', amount: 1, category: 'x', recurrence: 'none' },
        { id: 'a1', name: 'Dup', amount: 1, category: 'x', dueDate: '2026-01-31', recurrence: 'none' },
        null,
        'str',
      ],
      inv: [{ id: 'i1', name: 'Fund', invested: 10 }],
      loans: [{ id: 'l1', name: 'L', principal: 1, outstanding: 1, rate: 1, emi: 1, emiDay: 1, start: '2026-02-30', end: '2030-01-01' }],
    };
    const r = repairCollections(o);
    const bills = o.bills as Array<Record<string, unknown>>;
    expect(bills).toHaveLength(1);
    expect(bills[0]!.history).toEqual([{ date: '2026-01-01', amount: 5 }]);
    expect(bills[0]).not.toHaveProperty('evil');
    expect(o.inv as unknown[]).toHaveLength(1);
    expect(o.loans as unknown[]).toHaveLength(0); // 30 Feb is not a date
    expect(o.gold).toEqual([]);
    expect(r.dropped).toBe(5);
  });
  it('only keeps well-formed file ids', () => {
    const o: Record<string, unknown> = { docs: [{ id: 'd1', name: 'x', category: 'y', file_id: '../../etc/passwd' }, { id: 'd2', name: 'x', category: 'y', file_id: 'a'.repeat(32) }] };
    repairCollections(o);
    const d = o.docs as Array<Record<string, unknown>>;
    expect(d[0]).not.toHaveProperty('file_id');
    expect(d[1]!.file_id).toBe('a'.repeat(32));
  });
});
