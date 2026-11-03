import { isNative } from './env';
import { toB64 } from '../security/bytes';

/** Hands an (already encrypted) backup file to the user: Android share sheet, or a download in a browser. */
export async function deliverBackup(fileName: string, bytes: Uint8Array): Promise<'shared' | 'downloaded'> {
  if (isNative()) {
    const [{ Filesystem, Directory }, { Share }] = await Promise.all([import('@capacitor/filesystem'), import('@capacitor/share')]);
    const w = await Filesystem.writeFile({ path: fileName, data: toB64(bytes), directory: Directory.Cache });
    try {
      await Share.share({ title: 'My Life Manager backup', dialogTitle: 'Save your encrypted backup', url: w.uri });
    } finally {
      // The file is encrypted, but there is no reason to leave a copy in the cache.
      setTimeout(() => void Filesystem.deleteFile({ path: fileName, directory: Directory.Cache }).catch(() => undefined), 120_000);
    }
    return 'shared';
  }
  const url = URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return 'downloaded';
}
