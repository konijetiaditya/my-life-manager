import { argon2id } from 'hash-wasm';
import { concat, randomBytes, utf8, type Bytes } from './bytes';

/** Thrown whenever authenticated decryption fails: wrong key, damaged or tampered data. */
export class CryptoError extends Error {
  constructor(message = 'Decryption failed') {
    super(message);
    this.name = 'CryptoError';
  }
}

export interface ArgonParams {
  /** Memory in KiB. */
  m: number;
  /** Iterations. */
  t: number;
  /** Parallelism. */
  p: number;
}

/** Used to stretch the 4-digit PIN. Chosen to stay quick on mid-range phones. */
export const PIN_KDF: ArgonParams = { m: 19456, t: 2, p: 1 };
/** Used for backup passwords. Heavier because the backup file leaves the device. */
export const BACKUP_KDF: ArgonParams = { m: 65536, t: 3, p: 1 };

const FORMAT_V1 = 1;
const IV_LEN = 12;

export async function argon2(secret: string | Uint8Array, salt: Uint8Array, p: ArgonParams): Promise<Bytes> {
  const out = await argon2id({
    password: secret,
    salt,
    parallelism: p.p,
    iterations: p.t,
    memorySize: p.m,
    hashLength: 32,
    outputType: 'binary',
  });
  return new Uint8Array(out);
}

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, bytes = 32): Promise<Bytes> {
  const base = await crypto.subtle.importKey('raw', ikm as Bytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as Bytes, info: utf8(info) },
    base,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

export function aesKeyFromRaw(raw: Uint8Array, usages: KeyUsage[], extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as Bytes, { name: 'AES-GCM' }, extractable, usages);
}

/** Output layout: version(1) | iv(12) | ciphertext+tag. A fresh random IV is used for every call. */
export async function seal(key: CryptoKey, data: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  const iv = randomBytes(IV_LEN);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad as Bytes, tagLength: 128 },
    key,
    data as Bytes,
  );
  return concat(new Uint8Array([FORMAT_V1]), iv, new Uint8Array(ct));
}

export async function open(key: CryptoKey, blob: Uint8Array, aad: Uint8Array): Promise<Bytes> {
  if (blob.length < 1 + IV_LEN + 16 || blob[0] !== FORMAT_V1) throw new CryptoError('Unknown or damaged data format');
  const iv = blob.slice(1, 1 + IV_LEN);
  const ct = blob.slice(1 + IV_LEN);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad as Bytes, tagLength: 128 },
      key,
      ct,
    );
    return new Uint8Array(pt);
  } catch {
    throw new CryptoError();
  }
}

/** Wrap (encrypt) a data key with a key-encryption key. Layout: iv(12) | wrapped. */
export async function wrapDek(kek: CryptoKey, dek: CryptoKey, aad: Uint8Array): Promise<Bytes> {
  const iv = randomBytes(IV_LEN);
  const wrapped = await crypto.subtle.wrapKey('raw', dek, kek, {
    name: 'AES-GCM',
    iv,
    additionalData: aad as Bytes,
    tagLength: 128,
  });
  return concat(iv, new Uint8Array(wrapped));
}

/** Unwrap a data key. The result is non-extractable unless asked otherwise. */
export async function unwrapDek(kek: CryptoKey, blob: Uint8Array, aad: Uint8Array, extractable = false): Promise<CryptoKey> {
  if (blob.length < IV_LEN + 32 + 16) throw new CryptoError('Damaged key data');
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      blob.slice(IV_LEN),
      kek,
      { name: 'AES-GCM', iv: blob.slice(0, IV_LEN), additionalData: aad as Bytes, tagLength: 128 },
      { name: 'AES-GCM' },
      extractable,
      ['encrypt', 'decrypt'],
    );
  } catch {
    throw new CryptoError();
  }
}

export function kekFromRaw(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as Bytes, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
}
