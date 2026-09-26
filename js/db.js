// IndexedDB 适配器：manifests（文件级元数据+密钥）与 chunks（分片密文/哈希）。
const DB_NAME = 'chunk-crypt';
const DB_VERSION = 1;

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('manifests')) db.createObjectStore('manifests', { keyPath: 'fileId' });
      if (!db.objectStoreNames.contains('chunks')) {
        const s = db.createObjectStore('chunks', { keyPath: ['fileId', 'index'] });
        s.createIndex('byFile', 'fileId', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, store, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const s = t.objectStore(store);
    const out = fn(s);
    t.oncomplete = () => resolve(out && out._result !== undefined ? out._result : undefined);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('transaction aborted'));
  });
}

function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export class IdbStorage {
  async _db() { return this._p || (this._p = open()); }

  async getManifest(fileId) {
    const db = await this._db();
    return tx(db, 'manifests', 'readonly', (s) => reqToPromise(s.get(fileId)).then(r => { this._m = r; })).then(() => this._m);
  }
  async putManifest(m) {
    const db = await this._db();
    return tx(db, 'manifests', 'readwrite', (s) => s.put(m));
  }
  async deleteManifest(fileId) {
    const db = await this._db();
    return tx(db, 'manifests', 'readwrite', (s) => s.delete(fileId));
  }
  async putChunk(fileId, record) {
    const db = await this._db();
    return tx(db, 'chunks', 'readwrite', (s) => s.put(record));
  }
  async getChunks(fileId) {
    const db = await this._db();
    let result;
    await tx(db, 'chunks', 'readonly', (s) =>
      reqToPromise(s.index('byFile').getAll(fileId)).then((r) => { result = r; }));
    return result || [];
  }
  async deleteChunks(fileId) {
    const db = await this._db();
    return tx(db, 'chunks', 'readwrite', (s) => {
      const idx = s.index('byFile');
      idx.openCursor(IDBKeyRange.only(fileId)).onsuccess = (e) => {
        const cur = e.target.result;
        if (cur) { cur.delete(); cur.continue(); }
      };
    });
  }
  async estimate() {
    if (navigator.storage && navigator.storage.estimate) return navigator.storage.estimate();
    return { quota: 0, usage: 0 };
  }
}
