/** Rejects PINs that are among the first things anyone would try. A 4-digit PIN is a small space
 *  (10,000 values), so we at least take the most predictable ones out of it. */
const COMMON = new Set([
  '1234', '4321', '1111', '0000', '2580', '0852', '1212', '2112', '1122', '1004', '2000', '1010',
  '6969', '1313', '4200', '0007', '1379', '2468', '1357', '9876', '5683', '2001', '1999', '2020',
]);

export function pinWeakness(pin: string): string | null {
  if (!/^\d{4}$/.test(pin)) return 'Use exactly 4 digits.';
  const d = [...pin].map(Number) as [number, number, number, number];
  if (d.every((x) => x === d[0])) return 'That PIN is too easy to guess (repeated digit).';
  const step = d[1] - d[0];
  if ((step === 1 || step === -1) && d[2] - d[1] === step && d[3] - d[2] === step) return 'That PIN is too easy to guess (a run of digits).';
  if (d[0] === d[2] && d[1] === d[3]) return 'That PIN is too easy to guess (a repeating pair).';
  if (COMMON.has(pin)) return 'That PIN is very common. Pick something less obvious.';
  return null;
}
