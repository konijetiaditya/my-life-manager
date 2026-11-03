import { describe, expect, it } from 'vitest';
import { newVault, freshDb } from './helpers';
import { idbGet, idbKeys } from '../src/security/store';
import { Vault, VaultDamagedError } from '../src/security/vault';
import { MemorySecretStore } from '../src/platform/secretStore';
import { fromUtf8 } from '../src/security/bytes';

const SECRET_TEXT = 'Home loan EMI 38500 TOP-SECRET-MARKER';

describe('vault encryption', () => {
  it('creates a vault, saves and reloads data', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save(JSON.stringify({ note: SECRET_TEXT }));
    expect(JSON.parse((await vault.load())!).note).toBe(SECRET_TEXT);
  });

  it('stores nothing readable: no plaintext in the vault, meta or file records', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save(JSON.stringify({ note: SECRET_TEXT }));
    const id = await vault.putFile(new TextEncoder().encode('%PDF-1.4 secret file body ' + SECRET_TEXT));
    const blobs: Uint8Array[] = [(await idbGet<Uint8Array>('vault', 'main'))!, (await idbGet<Uint8Array>('files', id))!];
    for (const b of blobs) {
      const asText = Buffer.from(b).toString('latin1');
      expect(asText.includes('TOP-SECRET-MARKER')).toBe(false);
      expect(asText.includes('Home loan')).toBe(false);
    }
    const meta = JSON.stringify(await idbGet('meta', 'main'));
    expect(meta.includes('1234')).toBe(false);
    expect(meta.includes('TOP-SECRET')).toBe(false);
  });

  it('uses a different nonce every time (same data encrypts differently)', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save('{"a":1}');
    const a = Buffer.from((await idbGet<Uint8Array>('vault', 'main'))!).toString('hex');
    await vault.save('{"a":1}');
    const b = Buffer.from((await idbGet<Uint8Array>('vault', 'main'))!).toString('hex');
    expect(a).not.toBe(b);
  });

  it('keeps the data key non-extractable', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    const key = (vault as unknown as { dek: CryptoKey }).dek;
    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  });

  it('unlocks with the right PIN and refuses the wrong one', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":1}');
    vault.lock();
    expect(vault.isUnlocked).toBe(false);
    await expect(vault.load()).rejects.toThrow('locked');
    expect(await vault.unlockWithPin('0000')).toMatchObject({ ok: false, reason: 'wrong' });
    expect(vault.isUnlocked).toBe(false);
    expect(await vault.unlockWithPin('1234')).toEqual({ ok: true });
    expect(JSON.parse((await vault.load())!).x).toBe(1);
  });

  it('rejects malformed PINs without counting them as guesses', async () => {
    const { vault, lockout } = await newVault();
    await vault.create('1234');
    vault.lock();
    expect(await vault.unlockWithPin('12')).toMatchObject({ ok: false, reason: 'format' });
    expect(await vault.unlockWithPin('abcd')).toMatchObject({ ok: false, reason: 'format' });
    expect(await lockout.fails()).toBe(0);
    await expect(vault.create('12345')).rejects.toThrow();
  });

  it('cannot be opened by the PIN alone if the Keystore device secret is missing', async () => {
    const { vault, secrets } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":1}');
    vault.lock();
    secrets.data.delete('mlm.device');
    expect(await vault.unlockWithPin('1234')).toMatchObject({ ok: false, reason: 'damaged' });
  });

  it('cannot be opened with the right PIN but a different device secret', async () => {
    const { vault, secrets } = await newVault();
    await vault.create('1234');
    vault.lock();
    secrets.data.set('mlm.device', Buffer.alloc(32, 7).toString('base64'));
    const r = await vault.unlockWithPin('1234');
    expect(r.ok).toBe(false);
  });

  it('detects tampering with stored data (flipped byte)', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":1}');
    const blob = (await idbGet<Uint8Array>('vault', 'main'))!.slice();
    blob[blob.length - 5] = blob[blob.length - 5]! ^ 0xff;
    const { idbPut } = await import('../src/security/store');
    await idbPut('vault', 'main', blob);
    await expect(vault.load()).rejects.toBeInstanceOf(VaultDamagedError);
  });

  it('refuses a vault record copied into the file store (data is bound to its purpose)', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":1}');
    const { idbPut } = await import('../src/security/store');
    const id = 'a'.repeat(32);
    await idbPut('files', id, (await idbGet<Uint8Array>('vault', 'main'))!);
    await expect(vault.getFile(id)).rejects.toBeInstanceOf(VaultDamagedError);
  });

  it('refuses file ids that are not 32 hex characters (no path tricks)', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await expect(vault.getFile('../../etc/passwd')).rejects.toThrow('Invalid file id');
    await vault.deleteFile('../x');
  });

  it('stores, reads and deletes attached files', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    const id = await vault.putFile(new TextEncoder().encode('%PDF-1.4 hello'));
    expect(fromUtf8(await vault.getFile(id))).toBe('%PDF-1.4 hello');
    expect(await vault.fileIds()).toContain(id);
    await vault.deleteFile(id);
    expect(await idbKeys('files')).not.toContain(id);
  });

  it('changes the PIN: old PIN stops working, data survives', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":42}');
    expect(await vault.changePin('1234', '9876')).toEqual({ ok: true });
    vault.lock();
    expect((await vault.unlockWithPin('1234')).ok).toBe(false);
    expect(await vault.unlockWithPin('9876')).toEqual({ ok: true });
    expect(JSON.parse((await vault.load())!).x).toBe(42);
  });

  it('biometric path: unlocks only after enable, and stops after disable', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":7}');
    vault.lock();
    expect((await vault.unlockAfterBiometric()).ok).toBe(false);
    await vault.unlockWithPin('1234');
    expect(await vault.enableBiometric('1234')).toEqual({ ok: true });
    expect(await vault.biometricEnabled()).toBe(true);
    vault.lock();
    expect(await vault.unlockAfterBiometric()).toEqual({ ok: true });
    expect(JSON.parse((await vault.load())!).x).toBe(7);
    await vault.disableBiometric();
    vault.lock();
    expect((await vault.unlockAfterBiometric()).ok).toBe(false);
    expect(await vault.unlockWithPin('1234')).toEqual({ ok: true });
  });

  it('enabling biometrics requires the correct PIN', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    expect((await vault.enableBiometric('0000')).ok).toBe(false);
    expect(await vault.biometricEnabled()).toBe(false);
  });

  it('wipe removes data, keys and counters', async () => {
    const { vault, secrets } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":1}');
    await vault.putFile(new TextEncoder().encode('%PDF-1.4'));
    await vault.wipe();
    expect(await vault.exists()).toBe(false);
    expect(secrets.data.size).toBe(0);
    expect(await idbKeys('files')).toEqual([]);
    expect(await idbGet('vault', 'main')).toBeUndefined();
  });

  it('replaceAll swaps data and files atomically', async () => {
    const { vault } = await newVault();
    await vault.create('1234');
    const oldId = await vault.putFile(new TextEncoder().encode('%PDF-1.4 old'));
    const newId = 'b'.repeat(32);
    await vault.replaceAll('{"y":2}', [{ id: newId, bytes: new TextEncoder().encode('%PDF-1.4 new') }]);
    expect(JSON.parse((await vault.load())!).y).toBe(2);
    expect(await vault.fileIds()).toEqual([newId]);
    await expect(vault.getFile(oldId)).rejects.toThrow();
  });

  it('a second vault instance with the same stores can unlock (restart simulation)', async () => {
    const { vault, secrets, lockout } = await newVault();
    await vault.create('1234');
    await vault.save('{"x":5}');
    const again = new Vault(secrets, lockout, { m: 8192, t: 1, p: 1 });
    expect(await again.exists()).toBe(true);
    expect(await again.unlockWithPin('1234')).toEqual({ ok: true });
    expect(JSON.parse((await again.load())!).x).toBe(5);
  });

  it('freshDb really isolates tests', async () => {
    await freshDb();
    const v = new Vault(new MemorySecretStore());
    expect(await v.exists()).toBe(false);
  });
});
