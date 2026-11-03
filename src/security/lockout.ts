import type { SecretStore } from '../platform/secretStore';

const KEY = 'mlm.lockout';

/** Wait imposed before the next PIN attempt, given how many wrong attempts have been made in a row. */
export function delayForFails(fails: number): number {
  if (fails < 3) return 0;
  if (fails === 3) return 30_000;
  if (fails === 4) return 60_000;
  if (fails === 5) return 120_000;
  if (fails === 6) return 300_000;
  return 900_000;
}

interface State {
  fails: number;
  until: number;
  seen: number;
}

/**
 * Counts wrong PIN attempts and imposes growing waits. The counter lives in the secure store
 * (not in the main vault) and is increased BEFORE a PIN is checked, so closing the app in the
 * middle of an attempt cannot be used to dodge the count. The clock cannot be wound back past
 * the latest time the app has already seen.
 */
export class Lockout {
  constructor(
    private readonly store: SecretStore,
    private readonly now: () => number = () => Date.now(),
  ) {}

  private async read(): Promise<State> {
    const raw = await this.store.get(KEY);
    if (!raw) return { fails: 0, until: 0, seen: 0 };
    try {
      const s = JSON.parse(raw) as Partial<State>;
      if (typeof s.fails === 'number' && typeof s.until === 'number' && typeof s.seen === 'number') {
        return { fails: s.fails, until: s.until, seen: s.seen };
      }
    } catch {
      /* fall through */
    }
    // A damaged counter is treated as a hostile state: start from a long wait, not from zero.
    return { fails: 7, until: this.now() + 900_000, seen: this.now() };
  }

  private write(s: State): Promise<void> {
    return this.store.set(KEY, JSON.stringify(s));
  }

  async waitMs(): Promise<number> {
    const s = await this.read();
    const now = Math.max(this.now(), s.seen);
    if (now !== s.seen) await this.write({ ...s, seen: now });
    return Math.max(0, s.until - now);
  }

  /** Call before verifying a PIN. Returns the number of wrong attempts including this one. */
  async recordAttempt(): Promise<number> {
    const s = await this.read();
    const now = Math.max(this.now(), s.seen);
    const fails = s.fails + 1;
    await this.write({ fails, until: now + delayForFails(fails), seen: now });
    return fails;
  }

  async fails(): Promise<number> {
    return (await this.read()).fails;
  }

  async reset(): Promise<void> {
    await this.store.remove(KEY);
  }
}
