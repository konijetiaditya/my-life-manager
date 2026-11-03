import { describe, expect, it } from 'vitest';
import { BackupError, checkBackupPassword, createBackup, readBackup } from '../src/security/backup';
import { concat, u32, utf8 } from '../src/security/bytes';
import { FAST } from './helpers';

const files = [
  { id: 'a'.repeat(32), bytes: utf8('%PDF-1.4 first file') },
  { id: 'b'.repeat(32), bytes: utf8('%PDF-1.4 second file') },
];
const STATE = JSON.stringify({ bills: [{ id: 'x1', name: 'BACKUP-SECRET-NAME' }] });
const PW = 'correct horse battery';

describe('encrypted backup', () => {
  it('round-trips data and files', async () => {
    const b = await createBackup(STATE, files, PW, FAST);
    const r = await readBackup(b, PW);
    expect(r.stateJson).toBe(STATE);
    expect(r.files.map((f) => f.id)).toEqual(files.map((f) => f.id));
    expect(Buffer.from(r.files[1]!.bytes).toString()).toBe('%PDF-1.4 second file');
  });

  it('contains no readable content', async () => {
    const b = await createBackup(STATE, files, PW, FAST);
    const text = Buffer.from(b).toString('latin1');
    expect(text.includes('BACKUP-SECRET-NAME')).toBe(false);
    expect(text.includes('second file')).toBe(false);
  });

  it('rejects the wrong password', async () => {
    const b = await createBackup(STATE, files, PW, FAST);
    await expect(readBackup(b, 'not the password!!')).rejects.toBeInstanceOf(BackupError);
  });

  it('rejects any flipped byte (header, entry body, final byte)', async () => {
    const b = await createBackup(STATE, files, PW, FAST);
    for (const pos of [12, 60, b.length - 1, Math.floor(b.length / 2)]) {
      const t = b.slice();
      t[pos] = t[pos]! ^ 1;
      await expect(readBackup(t, PW)).rejects.toBeInstanceOf(BackupError);
    }
  });

  it('rejects truncation and appended data', async () => {
    const b = await createBackup(STATE, files, PW, FAST);
    await expect(readBackup(b.slice(0, b.length - 10), PW)).rejects.toBeInstanceOf(BackupError);
    await expect(readBackup(concat(b, new Uint8Array([1, 2, 3])), PW)).rejects.toBeInstanceOf(BackupError);
  });

  it('rejects swapped entries (reordering is detected)', async () => {
    const b = await createBackup(STATE, files, PW, FAST);
    // find entry boundaries: prefix length from header
    const hLen = new DataView(b.buffer, b.byteOffset).getUint32(6, false);
    let off = 10 + hLen;
    const spans: Array<[number, number]> = [];
    while (off < b.length) {
      const len = new DataView(b.buffer, b.byteOffset).getUint32(off, false);
      spans.push([off, off + 4 + len]);
      off += 4 + len;
    }
    const [e1, e2] = [b.slice(spans[1]![0], spans[1]![1]), b.slice(spans[2]![0], spans[2]![1])];
    const swapped = concat(b.slice(0, spans[1]![0]), e2, e1);
    await expect(readBackup(swapped, PW)).rejects.toBeInstanceOf(BackupError);
  });

  it('rejects files that are not backups and absurd KDF settings', async () => {
    await expect(readBackup(utf8('hello world, not a backup at all'), PW)).rejects.toBeInstanceOf(BackupError);
    const header = utf8(JSON.stringify({ kdf: { m: 4294967295, t: 1, p: 1 }, salt: 'AAAA', ids: [] }));
    const evil = concat(utf8('MLMBK'), new Uint8Array([1]), u32(header.length), header, u32(0));
    await expect(readBackup(evil, PW)).rejects.toBeInstanceOf(BackupError);
  });

  it('enforces a minimum password strength', async () => {
    expect(checkBackupPassword('short')).not.toBeNull();
    expect(checkBackupPassword('aaaaaaaaaaaa')).not.toBeNull();
    expect(checkBackupPassword('a decent passphrase')).toBeNull();
    await expect(createBackup(STATE, files, 'short', FAST)).rejects.toBeInstanceOf(BackupError);
  });

  it('two backups of the same data differ (random salt and nonces)', async () => {
    const a = await createBackup(STATE, files, PW, FAST);
    const b = await createBackup(STATE, files, PW, FAST);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});
