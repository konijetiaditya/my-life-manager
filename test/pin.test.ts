import { describe, expect, it } from 'vitest';
import { pinWeakness } from '../src/security/pinPolicy';

describe('pinWeakness', () => {
  it.each(['0000', '1111', '1234', '4321', '0123', '3210', '2580', '1212', '7878', '9876'])('rejects %s', (p) => {
    expect(pinWeakness(p)).not.toBeNull();
  });
  it.each(['4827', '1359', '7305', '2946'])('accepts %s', (p) => {
    expect(pinWeakness(p)).toBeNull();
  });
  it('rejects wrong formats', () => {
    for (const p of ['', '123', '12345', 'abcd', '12 4']) expect(pinWeakness(p)).not.toBeNull();
  });
});
