import { BACKUP_KDF, CryptoError, aesKeyFromRaw, argon2, open, seal, type ArgonParams } from './crypto';
import { concat, fromB64, fromUtf8, randomBytes, readU32, toB64, u32, utf8, type Bytes } from './bytes';
import { FILE_ID_PATTERN } from './vault';

export const MIN_BACKUP_PASSWORD = 10;
const MAGIC = utf8('MLMBK');
const VERSION = 1;

export interface BackupFile {
  id: string;
  bytes: Uint8Array;
}

export class BackupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BackupError';
  }
}

export function checkBackupPassword(pw: string): string | null {
  if (pw.length < MIN_BACKUP_PASSWORD) return `Use at least ${MIN_BACKUP_PASSWORD} characters.`;
  if (/^(.)\1+$/.test(pw)) return 'Do not repeat a single character.';
  return null;
}

/**
 * Backup file layout:
 *   "MLMBK" | version(1) | headerLength(4) | header JSON | entries...
 *   entry = length(4) | AES-256-GCM sealed data
 * Entry 0 is the app data, entries 1..n are the attached files in the order listed in the header.
 * Every entry is bound to the header and to its position (as authenticated data), so entries
 * cannot be reordered, swapped between backups, or cut off without detection.
 */
export async function createBackup(stateJson: string, files: BackupFile[], password: string, kdf: ArgonParams = BACKUP_KDF): Promise<Bytes> {
  const pwErr = checkBackupPassword(password);
  if (pwErr) throw new BackupError(pwErr);
  const salt = randomBytes(16);
  const header = utf8(JSON.stringify({ kdf, salt: toB64(salt), ids: files.map((f) => f.id) }));
  const keyRaw = await argon2(password.normalize('NFKC'), salt, kdf);
  const key = await aesKeyFromRaw(keyRaw, ['encrypt', 'decrypt']);
  keyRaw.fill(0);
  const prefix = concat(MAGIC, new Uint8Array([VERSION]), u32(header.length), header);
  const aad = (i: number) => concat(prefix, u32(i));
  const parts: Uint8Array[] = [prefix];
  const entries = [utf8(stateJson), ...files.map((f) => f.bytes)];
  for (let i = 0; i < entries.length; i++) {
    const sealed = await seal(key, entries[i]!, aad(i));
    parts.push(u32(sealed.length), sealed);
  }
  return concat(...parts);
}

export async function readBackup(data: Uint8Array, password: string): Promise<{ stateJson: string; files: BackupFile[] }> {
  try {
    if (data.length < MAGIC.length + 5) throw new BackupError('This is not a My Life Manager backup.');
    for (let i = 0; i < MAGIC.length; i++) if (data[i] !== MAGIC[i]) throw new BackupError('This is not a My Life Manager backup.');
    if (data[MAGIC.length] !== VERSION) throw new BackupError('This backup was made by a newer version of the app.');
    const hLen = readU32(data, MAGIC.length + 1);
    const hStart = MAGIC.length + 5;
    if (hLen > 1_000_000 || hStart + hLen > data.length) throw new BackupError('The backup is damaged.');
    const header = data.slice(hStart, hStart + hLen);
    let h: { kdf: ArgonParams; salt: string; ids: string[] };
    try {
      h = JSON.parse(fromUtf8(header));
    } catch {
      throw new BackupError('The backup is damaged.');
    }
    const k = h.kdf;
    // Refuse absurd settings that a crafted file could use to exhaust memory or time.
    if (!k || !(k.m >= 8192 && k.m <= 262144) || !(k.t >= 1 && k.t <= 10) || !(k.p >= 1 && k.p <= 4)) throw new BackupError('The backup is damaged.');
    if (!Array.isArray(h.ids) || h.ids.length > 20000 || !h.ids.every((x) => typeof x === 'string' && FILE_ID_PATTERN.test(x))) throw new BackupError('The backup is damaged.');
    const keyRaw = await argon2(password.normalize('NFKC'), fromB64(h.salt), k);
    const key = await aesKeyFromRaw(keyRaw, ['encrypt', 'decrypt']);
    keyRaw.fill(0);
    const prefix = data.slice(0, hStart + hLen);
    let off = hStart + hLen;
    const out: Uint8Array[] = [];
    for (let i = 0; i < h.ids.length + 1; i++) {
      const len = readU32(data, off);
      off += 4;
      if (off + len > data.length) throw new BackupError('The backup is incomplete.');
      out.push(await open(key, data.slice(off, off + len), concat(prefix, u32(i))));
      off += len;
    }
    if (off !== data.length) throw new BackupError('The backup has unexpected extra data.');
    return {
      stateJson: fromUtf8(out[0]!),
      files: h.ids.map((id, i) => ({ id, bytes: out[i + 1]! })),
    };
  } catch (e) {
    if (e instanceof BackupError) throw e;
    if (e instanceof CryptoError) throw new BackupError('Wrong password, or the backup is damaged.');
    // Anything else (bad base64, bad UTF-8, short data) means the file is not a valid backup.
    throw new BackupError('The backup is damaged.');
  }
}
