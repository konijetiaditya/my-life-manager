import { isNative } from './env';
import { idbDelete, idbGet, idbPut } from '../security/store';
import { fromUtf8, utf8 } from '../security/bytes';

/**
 * Holds small secrets that must never sit next to the encrypted data:
 *  - the device secret that is mixed into (or, with app lock off, wraps) the data key
 *  - the biometric secret and the wrong-PIN counter (PIN mode only)
 * On Android these are kept by the Android Keystore through the secure-storage plugin.
 * In a plain browser (development and automated tests) a weaker IndexedDB store is used.
 */
export interface SecretStore {
  readonly hardwareBacked: boolean;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

class BrowserSecretStore implements SecretStore {
  readonly hardwareBacked = false;
  async get(key: string): Promise<string | null> {
    const v = await idbGet<Uint8Array>('secure', key);
    return v ? fromUtf8(v) : null;
  }
  async set(key: string, value: string): Promise<void> {
    await idbPut('secure', key, utf8(value));
  }
  async remove(key: string): Promise<void> {
    await idbDelete('secure', key);
  }
}

const NATIVE_WAIT_MS = 8000;

class NativeSecretStore implements SecretStore {
  readonly hardwareBacked = true;
  private plugin: Promise<typeof import('@aparajita/capacitor-secure-storage')['SecureStorage']> | null = null;

  private sec() {
    this.plugin ??= import('@aparajita/capacitor-secure-storage').then((m) => m.SecureStorage);
    return this.plugin;
  }

  async get(key: string): Promise<string | null> {
    const v = await (await this.sec()).get(key);
    return typeof v === 'string' ? v : null;
  }

  async set(key: string, value: string): Promise<void> {
    await (await this.sec()).set(key, value);
  }

  async remove(key: string): Promise<void> {
    await (await this.sec()).remove(key);
  }
}

function within<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('The key store did not answer')), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });
}

/**
 * Uses the primary store (the Android Keystore). If it throws or never answers, the secret goes to
 * the fallback (the app's private storage) instead, and `hardwareBacked` turns false so Settings can
 * say so honestly. The app never freezes waiting for the Keystore.
 */
export class ResilientSecretStore implements SecretStore {
  private degraded = false;
  constructor(
    private readonly primary: SecretStore,
    private readonly fallback: SecretStore,
    private readonly waitMs: number = NATIVE_WAIT_MS,
  ) {}

  get hardwareBacked(): boolean {
    return this.primary.hardwareBacked && !this.degraded;
  }

  async get(key: string): Promise<string | null> {
    try {
      const v = await within(this.primary.get(key), this.waitMs);
      if (v !== null) return v;
    } catch {
      /* use the fallback */
    }
    const f = await this.fallback.get(key);
    if (f !== null) this.degraded = true;
    return f;
  }

  async set(key: string, value: string): Promise<void> {
    try {
      await within(this.primary.set(key, value), this.waitMs);
      await this.fallback.remove(key).catch(() => undefined);
    } catch {
      this.degraded = true;
      await this.fallback.set(key, value);
    }
  }

  async remove(key: string): Promise<void> {
    await within(this.primary.remove(key), this.waitMs).catch(() => undefined);
    await this.fallback.remove(key).catch(() => undefined);
  }
}

/** Simple in-memory store used by unit tests. */
export class MemorySecretStore implements SecretStore {
  readonly hardwareBacked = false;
  readonly data = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.data.get(key) ?? null;
  }
  async set(key: string, value: string): Promise<void> {
    this.data.set(key, value);
  }
  async remove(key: string): Promise<void> {
    this.data.delete(key);
  }
}

let current: SecretStore | null = null;
export function getSecretStore(): SecretStore {
  current ??= isNative() ? new ResilientSecretStore(new NativeSecretStore(), new BrowserSecretStore()) : new BrowserSecretStore();
  return current;
}
