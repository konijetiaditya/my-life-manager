/** Minimal promise wrapper around IndexedDB. Everything stored here is already encrypted
 *  (except the 'secure' browser-fallback store, which is only used outside the Android app). */
const DB_NAME = 'mlm-vault';
const DB_VERSION = 1;
export type StoreName = 'meta' | 'vault' | 'files' | 'secure';
const STORES: StoreName[] = ['meta', 'vault', 'files', 'secure'];

let dbPromise: Promise<IDBDatabase> | null = null;

function open(): Promise<IDBDatabase> {
  dbPromise ??= new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      for (const s of STORES) if (!req.result.objectStoreNames.contains(s)) req.result.createObjectStore(s);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      dbPromise = null;
      reject(req.error ?? new Error('Storage unavailable'));
    };
  });
  return dbPromise;
}

/** Close the cached connection (used by tests that reset the database). */
export async function idbClose(): Promise<void> {
  if (dbPromise) {
    (await dbPromise).close();
    dbPromise = null;
  }
}

function wrap<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function idbGet<T>(store: StoreName, key: string): Promise<T | undefined> {
  const db = await open();
  return wrap<T | undefined>(db.transaction(store, 'readonly').objectStore(store).get(key));
}

export async function idbPut(store: StoreName, key: string, value: unknown): Promise<void> {
  const db = await open();
  const tx = db.transaction(store, 'readwrite');
  tx.objectStore(store).put(value, key);
  await txDone(tx);
}

export async function idbDelete(store: StoreName, key: string): Promise<void> {
  const db = await open();
  const tx = db.transaction(store, 'readwrite');
  tx.objectStore(store).delete(key);
  await txDone(tx);
}

export async function idbKeys(store: StoreName): Promise<string[]> {
  const db = await open();
  return (await wrap(db.transaction(store, 'readonly').objectStore(store).getAllKeys())).map(String);
}

export async function idbClearAll(stores: StoreName[] = STORES): Promise<void> {
  const db = await open();
  const tx = db.transaction(stores, 'readwrite');
  for (const s of stores) tx.objectStore(s).clear();
  await txDone(tx);
}

/** Run several writes as ONE transaction: either all of them happen or none do. */
export async function idbBatch(ops: Array<{ store: StoreName; key: string; value?: unknown; del?: boolean }>, clear: StoreName[] = []): Promise<void> {
  const db = await open();
  const names = Array.from(new Set([...ops.map((o) => o.store), ...clear]));
  const tx = db.transaction(names, 'readwrite');
  for (const c of clear) tx.objectStore(c).clear();
  for (const o of ops) {
    if (o.del) tx.objectStore(o.store).delete(o.key);
    else tx.objectStore(o.store).put(o.value, o.key);
  }
  await txDone(tx);
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error('Storage write cancelled'));
  });
}
