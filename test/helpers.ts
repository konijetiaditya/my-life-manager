import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { idbClose } from '../src/security/store';
import { MemorySecretStore } from '../src/platform/secretStore';
import { Vault } from '../src/security/vault';
import { Lockout } from '../src/security/lockout';
import type { ArgonParams } from '../src/security/crypto';

/** Fast Argon2 settings so unit tests stay quick. Production values are in crypto.ts. */
export const FAST: ArgonParams = { m: 8192, t: 1, p: 1 };

export async function freshDb(): Promise<void> {
  await idbClose();
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

export async function newVault(now: () => number = () => Date.now()) {
  await freshDb();
  const secrets = new MemorySecretStore();
  const lockout = new Lockout(secrets, now);
  const vault = new Vault(secrets, lockout, FAST);
  return { vault, secrets, lockout };
}
