// IndexedDB 封装：会话元数据 + 加密分片存储
const DB_NAME = 'chunkcrypt';
const DB_VERSION = 1;

export function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('chunks')) {
        const store = db.createObjectStore('chunks', { keyPath: 'key' });
        store.createIndex('bySession', 'sessionId', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveSession(db, session) {
  const t = db.transaction('sessions', 'readwrite');
  t.objectStore('sessions').put(session);
  return new Promise((resolve, reject) => {
    t.oncomplete = resolve;
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('transaction aborted'));
  });
}

export async function getSession(db, id) {
  const t = db.transaction('sessions', 'readonly');
  return reqToPromise(t.objectStore('sessions').get(id));
}

export async function listSessions(db) {
  const t = db.transaction('sessions', 'readonly');
  return reqToPromise(t.objectStore('sessions').getAll());
}

export async function findSessionByFile(db, name, size, lastModified) {
  const all = await listSessions(db);
  return all.find(
    (s) => s.fileName === name && s.fileSize === size && s.lastModified === lastModified && s.status !== 'done'
  ) || null;
}

export async function deleteSession(db, id) {
  const t = db.transaction(['sessions', 'chunks'], 'readwrite');
  t.objectStore('sessions').delete(id);
  const idx = t.objectStore('chunks').index('bySession');
  const keys = await reqToPromise(idx.getAllKeys(IDBKeyRange.only(id)));
  for (const k of keys) t.objectStore('chunks').delete(k);
  return new Promise((resolve, reject) => {
    t.oncomplete = resolve;
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('transaction aborted'));
  });
}

export async function putChunk(db, sessionId, index, data) {
  const t = db.transaction('chunks', 'readwrite');
  t.objectStore('chunks').put({ key: `${sessionId}:${index}`, sessionId, index, data });
  return new Promise((resolve, reject) => {
    t.oncomplete = resolve;
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('transaction aborted'));
  });
}

export async function getChunk(db, sessionId, index) {
  const t = db.transaction('chunks', 'readonly');
  const row = await reqToPromise(t.objectStore('chunks').get(`${sessionId}:${index}`));
  return row ? row.data : null;
}

export async function countChunks(db, sessionId) {
  const t = db.transaction('chunks', 'readonly');
  const idx = t.objectStore('chunks').index('bySession');
  return reqToPromise(idx.count(IDBKeyRange.only(sessionId)));
}
