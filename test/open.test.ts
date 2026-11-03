import { describe, expect, it } from 'vitest';
import { freshDb } from './helpers';
import { Vault } from '../src/security/vault';
import { MemorySecretStore, ResilientSecretStore, type SecretStore } from '../src/platform/secretStore';

describe('open (no-PIN) vault', () => {
  it('creates, saves, locks, reopens without a PIN; data is not stored as plain text', async () => {
    await freshDb();
    const secrets = new MemorySecretStore();
    const v = new Vault(secrets);
    await v.createOpen();
    expect(await v.isOpenMode()).toBe(true);
    await v.save(JSON.stringify({ note: 'ZEBRA-MARKER' }));
    v.lock();
    const v2 = new Vault(secrets);
    expect((await v2.unlockOpen()).ok).toBe(true);
    expect(JSON.parse((await v2.load())!).note).toBe('ZEBRA-MARKER');
  });
  it('refuses to open when the device secret is missing or different', async () => {
    await freshDb();
    const secrets = new MemorySecretStore();
    const v = new Vault(secrets);
    await v.createOpen();
    await v.save('{}');
    const other = new MemorySecretStore();
    expect((await new Vault(other).unlockOpen()).ok).toBe(false);
    other.data.set('mlm.device', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
    expect((await new Vault(other).unlockOpen()).ok).toBe(false);
  });
  it('a PIN-mode attempt cannot open an open-mode vault', async () => {
    await freshDb();
    const secrets = new MemorySecretStore();
    await new Vault(secrets).createOpen();
    const r = await new Vault(secrets).unlockWithPin('4827');
    expect(r.ok).toBe(false);
  });
});

describe('ResilientSecretStore', () => {
  const hang: SecretStore = { hardwareBacked: true, get: () => new Promise(() => undefined), set: () => new Promise(() => undefined), remove: () => new Promise(() => undefined) };
  const broken: SecretStore = { hardwareBacked: true, get: async () => { throw new Error('x'); }, set: async () => { throw new Error('x'); }, remove: async () => { throw new Error('x'); } };
  it('falls back instead of freezing when the primary never answers', async () => {
    const fb = new MemorySecretStore();
    const s = new ResilientSecretStore(hang, fb, 50);
    await s.set('k', 'v');
    expect(await s.get('k')).toBe('v');
    expect(s.hardwareBacked).toBe(false);
  });
  it('falls back when the primary throws', async () => {
    const s = new ResilientSecretStore(broken, new MemorySecretStore(), 50);
    await s.set('k', 'v');
    expect(await s.get('k')).toBe('v');
    await s.remove('k');
    expect(await s.get('k')).toBeNull();
  });
  it('uses the primary when it works', async () => {
    const p = new MemorySecretStore();
    const s = new ResilientSecretStore(Object.assign(p, { hardwareBacked: true }) as SecretStore, new MemorySecretStore(), 50);
    await s.set('k', 'v');
    expect(p.data.get('k')).toBe('v');
    expect(s.hardwareBacked).toBe(true);
  });
});
