import { describe, expect, it } from 'vitest';
import { newVault } from './helpers';
import { delayForFails } from '../src/security/lockout';

describe('wrong-PIN lockout', () => {
  it('delay table grows', () => {
    expect([0, 1, 2, 3, 4, 5, 6, 7, 20].map(delayForFails)).toEqual([0, 0, 0, 30000, 60000, 120000, 300000, 900000, 900000]);
  });

  it('three wrong PINs trigger a wait, which blocks even the CORRECT PIN', async () => {
    let t = 1_000_000;
    const { vault } = await newVault(() => t);
    await vault.create('1234');
    vault.lock();
    expect(await vault.unlockWithPin('1111')).toMatchObject({ reason: 'wrong', attemptsBeforeWait: 2 });
    expect(await vault.unlockWithPin('2222')).toMatchObject({ reason: 'wrong', attemptsBeforeWait: 1 });
    expect(await vault.unlockWithPin('3333')).toMatchObject({ reason: 'locked', waitMs: 30000 });
    expect(await vault.unlockWithPin('1234')).toMatchObject({ reason: 'locked' });
    expect(vault.isUnlocked).toBe(false);
    t += 31_000;
    expect(await vault.unlockWithPin('1234')).toEqual({ ok: true });
  });

  it('waits grow with more failures', async () => {
    let t = 5_000_000;
    const { vault } = await newVault(() => t);
    await vault.create('1234');
    vault.lock();
    for (const p of ['1111', '2222', '3333']) await vault.unlockWithPin(p);
    t += 31_000;
    expect(await vault.unlockWithPin('4444')).toMatchObject({ reason: 'locked', waitMs: 60000 });
    t += 61_000;
    expect(await vault.unlockWithPin('5555')).toMatchObject({ reason: 'locked', waitMs: 120000 });
  });

  it('winding the clock back does not shorten the wait', async () => {
    let t = 9_000_000;
    const { vault } = await newVault(() => t);
    await vault.create('1234');
    vault.lock();
    for (const p of ['1111', '2222', '3333']) await vault.unlockWithPin(p);
    t -= 3_600_000;
    const r = await vault.unlockWithPin('1234');
    expect(r).toMatchObject({ ok: false, reason: 'locked' });
  });

  it('counts the attempt BEFORE checking (killing the app mid-check cannot reset it)', async () => {
    const { vault, lockout } = await newVault();
    await vault.create('1234');
    vault.lock();
    const p = vault.unlockWithPin('0000');
    await new Promise((r) => setTimeout(r, 0));
    await p;
    expect(await lockout.fails()).toBe(1);
  });

  it('a correct PIN resets the counter', async () => {
    const { vault, lockout } = await newVault();
    await vault.create('1234');
    vault.lock();
    await vault.unlockWithPin('0000');
    await vault.unlockWithPin('1111');
    expect(await lockout.fails()).toBe(2);
    expect(await vault.unlockWithPin('1234')).toEqual({ ok: true });
    expect(await lockout.fails()).toBe(0);
  });

  it('a damaged counter is treated as hostile (long wait), not as zero', async () => {
    const { vault, secrets } = await newVault();
    await vault.create('1234');
    vault.lock();
    secrets.data.set('mlm.lockout', 'garbage{{{');
    expect(await vault.unlockWithPin('1234')).toMatchObject({ ok: false, reason: 'locked' });
  });

  it('verifyPin (sensitive actions) shares the same counter', async () => {
    const { vault, lockout } = await newVault();
    await vault.create('1234');
    expect((await vault.verifyPin('0000')).ok).toBe(false);
    expect(await lockout.fails()).toBe(1);
    expect(await vault.verifyPin('1234')).toEqual({ ok: true });
  });
});
