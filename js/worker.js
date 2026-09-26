// Web Worker：接收分片 Blob，执行读取+加密+哈希，结果以 Transferable 零拷贝回传。
import { processChunk } from './chunk-core.js';

let key = null;
const controllers = new Map();

self.onmessage = async (e) => {
  const m = e.data;
  if (m.type === 'setKey') {
    key = await crypto.subtle.importKey('jwk', m.jwk, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    return;
  }
  if (m.type === 'abort') {
    const c = controllers.get(m.id);
    if (c) c.abort();
    return;
  }
  if (m.type === 'process') {
    const controller = new AbortController();
    controllers.set(m.id, controller);
    try {
      if (!key) throw new Error('worker key not initialized');
      const r = await processChunk(m.blob, key, m.index, controller.signal);
      self.postMessage(
        { type: 'done', id: m.id, index: m.index, iv: r.iv, cipher: r.cipher, plainHash: r.plainHash, cipherHash: r.cipherHash },
        [r.iv, r.cipher, r.plainHash, r.cipherHash] // Transferable：避免结构化克隆占内存
      );
    } catch (err) {
      self.postMessage({ type: 'error', id: m.id, index: m.index, error: String(err && err.message || err), name: err && err.name });
    } finally {
      controllers.delete(m.id);
    }
  }
};
