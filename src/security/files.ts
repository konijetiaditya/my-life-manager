/** Checks applied to every file the user attaches. Files are kept only inside the encrypted vault
 *  under random ids, so the original name is never used as a path on disk. */
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
export type FileKind = 'pdf' | 'png' | 'jpg';

const MIME: Record<FileKind, string> = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg' };
const EXT: Record<FileKind, string[]> = { pdf: ['.pdf'], png: ['.png'], jpg: ['.jpg', '.jpeg'] };

export const mimeFor = (k: FileKind): string => MIME[k];

/** Identify a file by its first bytes, not by what its name claims. */
export function sniff(b: Uint8Array): FileKind | null {
  if (b.length >= 5 && b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46 && b[4] === 0x2d) return 'pdf';
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return 'png';
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpg';
  return null;
}

/** Returns a safe display name, or null if the name must be refused. */
export function sanitizeFileName(raw: string): string | null {
  const name = raw.normalize('NFC').trim();
  if (name.length < 1 || name.length > 100) return null;
  if (/[\\/\u0000-\u001f\u007f]/.test(name) || name.includes('..')) return null;
  if (name.startsWith('.')) return null;
  if (!/^[\p{L}\p{N} ._\-()'’,&]+$/u.test(name)) return null;
  return name;
}

export type UploadCheck =
  | { ok: true; kind: FileKind; name: string; mime: string }
  | { ok: false; error: string };

export function validateUpload(rawName: string, bytes: Uint8Array, allowed: FileKind[] = ['pdf', 'png', 'jpg']): UploadCheck {
  const name = sanitizeFileName(rawName);
  if (!name) return { ok: false, error: 'This file name is not allowed. Rename the file using letters, numbers and spaces only.' };
  if (bytes.length === 0) return { ok: false, error: 'The file is empty.' };
  if (bytes.length > MAX_FILE_BYTES) return { ok: false, error: 'The file is larger than 10 MB.' };
  const kind = sniff(bytes);
  if (!kind || !allowed.includes(kind)) {
    return { ok: false, error: `Only ${allowed.map((k) => k.toUpperCase()).join(', ')} files are allowed.` };
  }
  const lower = name.toLowerCase();
  if (!EXT[kind].some((e) => lower.endsWith(e))) return { ok: false, error: 'The file content does not match its extension.' };
  return { ok: true, kind, name, mime: MIME[kind] };
}
