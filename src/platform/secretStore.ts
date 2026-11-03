import { isNative } from './env';
import { idbDelete, idbGet, idbPut } from '../security/store';
import { fromUtf8, utf8 } from '../security/bytes';

/**
 * Holds small secrets that must never sit next to the encrypted data:
 *  - the device secret that is mixed into the key that protects the vault
 *  - the biometric secret
 *  - the wrong-PIN counter
 * On Android these are kept by the Android Keystore through the secure-storage plugin.
 * In a plain browser (development and automated tests only) a weaker IndexedDB fallback is used.
 */
export interface SecretStore {
  readonly hardwareBacked: boolean;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

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
    try {
      await (await this.sec()).remove(key);
    } catch {
      /* removing a missing key is fine */
    }
  }
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
  current ??= isNative() ? new NativeSecretStore() : new BrowserSecretStore();
  return current;
}
