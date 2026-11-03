import {
  CryptoError, PIN_KDF, aesKeyFromRaw, argon2, hkdf, kekFromRaw, open, seal, unwrapDek, wrapDek, type ArgonParams,
} from './crypto';
import { fromB64, fromUtf8, randomBytes, toB64, toHex, utf8, concat, type Bytes } from './bytes';
import { idbBatch, idbClearAll, idbDelete, idbGet, idbKeys, idbPut } from './store';
import { Lockout, delayForFails } from './lockout';
import type { SecretStore } from '../platform/secretStore';

const META_KEY = 'main';
const DEVICE_KEY = 'mlm.device';
const BIO_KEY = 'mlm.bio';
const AAD_DEK = utf8('mlm/dek/v1');
const AAD_DEK_BIO = utf8('mlm/dek-bio/v1');
const AAD_VAULT = utf8('mlm/vault/v1');
const aadFile = (id: string) => utf8('mlm/file/v1/' + id);

export const PIN_PATTERN = /^\d{4}$/;
export const FILE_ID_PATTERN = /^[0-9a-f]{32}$/;

interface Meta {
  v: 1;
  /** 'open' = no PIN: the key is wrapped by the device secret only. */
  mode?: 'open';
  pinSalt: string;
  kekSalt: string;
  kdf: ArgonParams;
  wrappedDek: string;
  bio?: { salt: string; wrappedDek: string };
  createdAt: number;
}

export type UnlockResult =
  | { ok: true }
  | { ok: false; reason: 'wrong'; attemptsBeforeWait: number }
  | { ok: false; reason: 'locked'; waitMs: number }
  | { ok: false; reason: 'damaged' | 'format' };

export class VaultDamagedError extends Error {
  constructor(message = 'The stored data could not be read') {
    super(message);
    this.name = 'VaultDamagedError';
  }
}

/**
 * The encrypted vault.
 *
 * Key hierarchy:
 *   DEK  (random 256-bit AES-GCM key)  encrypts all data and all attached files.
 *   KEK  = HKDF( Argon2id(PIN) || deviceSecret )  wraps the DEK. The deviceSecret lives in the
 *          Android Keystore, so the stored files alone are not enough to try PINs offline.
 *   The DEK only exists in memory as a NON-EXTRACTABLE key and is dropped when the app locks.
 */
export class Vault {
  private dek: CryptoKey | null = null;
  readonly lockout: Lockout;

  constructor(
    private readonly secrets: SecretStore,
    lockout?: Lockout,
    private readonly kdf: ArgonParams = PIN_KDF,
  ) {
    this.lockout = lockout ?? new Lockout(secrets);
  }

  get isUnlocked(): boolean {
    return this.dek !== null;
  }

  get keysAreHardwareBacked(): boolean {
    return this.secrets.hardwareBacked;
  }

  private async meta(): Promise<Meta | null> {
    const m = await idbGet<Meta>('meta', META_KEY);
    return m ?? null;
  }

  async exists(): Promise<boolean> {
    return (await this.meta()) !== null;
  }

  async biometricEnabled(): Promise<boolean> {
    const m = await this.meta();
    return !!m?.bio && (await this.secrets.get(BIO_KEY)) !== null;
  }

  private async deriveKek(pin: string, pinSalt: Bytes, kekSalt: Bytes, kdf: ArgonParams, device: Bytes): Promise<CryptoKey> {
    const pinKey = await argon2(pin, pinSalt, kdf);
    const raw = await hkdf(concat(pinKey, device), kekSalt, 'mlm/kek/pin/v1');
    pinKey.fill(0);
    const kek = await kekFromRaw(raw);
    raw.fill(0);
    return kek;
  }

  async isOpenMode(): Promise<boolean> {
    return (await this.meta())?.mode === 'open';
  }

  /** First-time setup WITHOUT a PIN: the data key is wrapped only by a device secret. Data is still encrypted at rest. */
  async createOpen(): Promise<void> {
    if (await this.exists()) throw new Error('A vault already exists');
    const device = randomBytes(32);
    const kekSalt = randomBytes(16);
    await this.secrets.set(DEVICE_KEY, toB64(device));
    try {
      const raw = await hkdf(device, kekSalt, 'mlm/kek/open/v1');
      const kek = await kekFromRaw(raw);
      raw.fill(0);
      const dekRaw = randomBytes(32);
      const extractable = await aesKeyFromRaw(dekRaw, ['encrypt', 'decrypt'], true);
      dekRaw.fill(0);
      const wrapped = await wrapDek(kek, extractable, AAD_DEK);
      const meta: Meta = { v: 1, mode: 'open', pinSalt: '', kekSalt: toB64(kekSalt), kdf: this.kdf, wrappedDek: toB64(wrapped), createdAt: Date.now() };
      await idbPut('meta', META_KEY, meta);
      this.dek = await unwrapDek(kek, wrapped, AAD_DEK, false);
    } catch (e) {
      await this.secrets.remove(DEVICE_KEY);
      throw e;
    } finally {
      device.fill(0);
    }
  }

  async unlockOpen(): Promise<UnlockResult> {
    const meta = await this.meta();
    if (!meta || meta.mode !== 'open') return { ok: false, reason: 'damaged' };
    const deviceB64 = await this.secrets.get(DEVICE_KEY);
    if (!deviceB64) return { ok: false, reason: 'damaged' };
    try {
      const raw = await hkdf(fromB64(deviceB64), fromB64(meta.kekSalt), 'mlm/kek/open/v1');
      const kek = await kekFromRaw(raw);
      raw.fill(0);
      this.dek = await unwrapDek(kek, fromB64(meta.wrappedDek), AAD_DEK, false);
      return { ok: true };
    } catch (e) {
      if (e instanceof CryptoError) return { ok: false, reason: 'damaged' };
      throw e;
    }
  }

  /** First-time setup: create all keys and protect them with the chosen PIN. */
  async create(pin: string): Promise<void> {
    if (!PIN_PATTERN.test(pin)) throw new Error('PIN must be exactly 4 digits');
    if (await this.exists()) throw new Error('A vault already exists');
    const device = randomBytes(32);
    const pinSalt = randomBytes(16);
    const kekSalt = randomBytes(16);
    await this.secrets.set(DEVICE_KEY, toB64(device));
    try {
      const kek = await this.deriveKek(pin, pinSalt, kekSalt, this.kdf, device);
      const dekRaw = randomBytes(32);
      const extractable = await aesKeyFromRaw(dekRaw, ['encrypt', 'decrypt'], true);
      dekRaw.fill(0);
      const wrapped = await wrapDek(kek, extractable, AAD_DEK);
      const meta: Meta = { v: 1, pinSalt: toB64(pinSalt), kekSalt: toB64(kekSalt), kdf: this.kdf, wrappedDek: toB64(wrapped), createdAt: Date.now() };
      await idbPut('meta', META_KEY, meta);
      this.dek = await unwrapDek(kek, wrapped, AAD_DEK, false);
      await this.lockout.reset();
    } catch (e) {
      await this.secrets.remove(DEVICE_KEY);
      throw e;
    } finally {
      device.fill(0);
    }
  }

  /** Counts the attempt first, then checks the PIN. Returns the unwrapped key on success. */
  private async tryPin(pin: string, extractable: boolean): Promise<{ key: CryptoKey } | { fail: UnlockResult }> {
    const meta = await this.meta();
    if (!meta) return { fail: { ok: false, reason: 'damaged' } };
    if (meta.mode === 'open') return { fail: { ok: false, reason: 'format' } };
    const wait = await this.lockout.waitMs();
    if (wait > 0) return { fail: { ok: false, reason: 'locked', waitMs: wait } };
    if (!PIN_PATTERN.test(pin)) return { fail: { ok: false, reason: 'format' } };
    const deviceB64 = await this.secrets.get(DEVICE_KEY);
    if (!deviceB64) return { fail: { ok: false, reason: 'damaged' } };
    const fails = await this.lockout.recordAttempt();
    const device = fromB64(deviceB64);
    try {
      const kek = await this.deriveKek(pin, fromB64(meta.pinSalt), fromB64(meta.kekSalt), meta.kdf, device);
      const key = await unwrapDek(kek, fromB64(meta.wrappedDek), AAD_DEK, extractable);
      await this.lockout.reset();
      return { key };
    } catch (e) {
      if (!(e instanceof CryptoError)) throw e;
      const wait2 = delayForFails(fails);
      if (wait2 > 0) return { fail: { ok: false, reason: 'locked', waitMs: wait2 } };
      return { fail: { ok: false, reason: 'wrong', attemptsBeforeWait: Math.max(0, 3 - fails) } };
    } finally {
      device.fill(0);
    }
  }

  async unlockWithPin(pin: string): Promise<UnlockResult> {
    const r = await this.tryPin(pin, false);
    if ('fail' in r) return r.fail;
    this.dek = r.key;
    return { ok: true };
  }

  /** Re-check the PIN while the app is already unlocked (for sensitive actions). */
  async verifyPin(pin: string): Promise<UnlockResult> {
    const r = await this.tryPin(pin, false);
    return 'fail' in r ? r.fail : { ok: true };
  }

  /** Call only AFTER the operating system has confirmed the user's biometrics. */
  async unlockAfterBiometric(): Promise<UnlockResult> {
    const meta = await this.meta();
    const secret = await this.secrets.get(BIO_KEY);
    if (!meta?.bio || !secret) return { ok: false, reason: 'damaged' };
    try {
      const raw = await hkdf(fromB64(secret), fromB64(meta.bio.salt), 'mlm/kek/bio/v1');
      const kek = await kekFromRaw(raw);
      raw.fill(0);
      this.dek = await unwrapDek(kek, fromB64(meta.bio.wrappedDek), AAD_DEK_BIO, false);
      return { ok: true };
    } catch (e) {
      if (e instanceof CryptoError) return { ok: false, reason: 'damaged' };
      throw e;
    }
  }

  async enableBiometric(pin: string): Promise<UnlockResult> {
    const r = await this.tryPin(pin, true);
    if ('fail' in r) return r.fail;
    const meta = (await this.meta())!;
    const secret = randomBytes(32);
    const salt = randomBytes(16);
    const raw = await hkdf(secret, salt, 'mlm/kek/bio/v1');
    const kek = await kekFromRaw(raw);
    raw.fill(0);
    const wrapped = await wrapDek(kek, r.key, AAD_DEK_BIO);
    await this.secrets.set(BIO_KEY, toB64(secret));
    secret.fill(0);
    await idbPut('meta', META_KEY, { ...meta, bio: { salt: toB64(salt), wrappedDek: toB64(wrapped) } } satisfies Meta);
    return { ok: true };
  }

  async disableBiometric(): Promise<void> {
    const meta = await this.meta();
    if (meta?.bio) {
      const { bio: _drop, ...rest } = meta;
      void _drop;
      await idbPut('meta', META_KEY, rest satisfies Meta);
    }
    await this.secrets.remove(BIO_KEY);
  }

  async changePin(oldPin: string, newPin: string): Promise<UnlockResult> {
    if (!PIN_PATTERN.test(newPin)) return { ok: false, reason: 'format' };
    const r = await this.tryPin(oldPin, true);
    if ('fail' in r) return r.fail;
    const meta = (await this.meta())!;
    const deviceB64 = await this.secrets.get(DEVICE_KEY);
    if (!deviceB64) return { ok: false, reason: 'damaged' };
    const pinSalt = randomBytes(16);
    const kekSalt = randomBytes(16);
    const kek = await this.deriveKek(newPin, pinSalt, kekSalt, this.kdf, fromB64(deviceB64));
    const wrapped = await wrapDek(kek, r.key, AAD_DEK);
    await idbPut('meta', META_KEY, { ...meta, pinSalt: toB64(pinSalt), kekSalt: toB64(kekSalt), kdf: this.kdf, wrappedDek: toB64(wrapped) } satisfies Meta);
    return { ok: true };
  }

  lock(): void {
    this.dek = null;
  }

  private key(): CryptoKey {
    if (!this.dek) throw new Error('Vault is locked');
    return this.dek;
  }

  async save(json: string): Promise<void> {
    const blob = await seal(this.key(), utf8(json), AAD_VAULT);
    await idbPut('vault', 'main', blob);
  }

  /** Returns the decrypted JSON text, or null when nothing has been saved yet. */
  async load(): Promise<string | null> {
    const blob = await idbGet<Uint8Array>('vault', 'main');
    if (!blob) return null;
    try {
      return fromUtf8(await open(this.key(), blob, AAD_VAULT));
    } catch (e) {
      if (e instanceof CryptoError) throw new VaultDamagedError();
      throw e;
    }
  }

  async putFile(bytes: Uint8Array): Promise<string> {
    const id = toHex(randomBytes(16));
    await idbPut('files', id, await seal(this.key(), bytes, aadFile(id)));
    return id;
  }

  async getFile(id: string): Promise<Bytes> {
    if (!FILE_ID_PATTERN.test(id)) throw new Error('Invalid file id');
    const blob = await idbGet<Uint8Array>('files', id);
    if (!blob) throw new VaultDamagedError('File not found');
    try {
      return await open(this.key(), blob, aadFile(id));
    } catch (e) {
      if (e instanceof CryptoError) throw new VaultDamagedError('This file is damaged');
      throw e;
    }
  }

  async deleteFile(id: string): Promise<void> {
    if (FILE_ID_PATTERN.test(id)) await idbDelete('files', id);
  }

  async fileIds(): Promise<string[]> {
    return idbKeys('files');
  }

  /** Replace everything (used by restore). One atomic transaction. */
  async replaceAll(json: string, files: Array<{ id: string; bytes: Uint8Array }>): Promise<void> {
    const key = this.key();
    const ops: Array<{ store: 'vault' | 'files'; key: string; value: unknown }> = [
      { store: 'vault', key: 'main', value: await seal(key, utf8(json), AAD_VAULT) },
    ];
    for (const f of files) {
      if (!FILE_ID_PATTERN.test(f.id)) throw new Error('Invalid file id in backup');
      ops.push({ store: 'files', key: f.id, value: await seal(key, f.bytes, aadFile(f.id)) });
    }
    await idbBatch(ops, ['files']);
  }

  /** Erase everything this app stores, including the keys. */
  async wipe(): Promise<void> {
    this.dek = null;
    await idbClearAll();
    await this.secrets.remove(DEVICE_KEY);
    await this.secrets.remove(BIO_KEY);
    await this.lockout.reset();
  }
}
