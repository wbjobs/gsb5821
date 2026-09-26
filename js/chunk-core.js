// 纯函数：读取一个分片 -> SHA-256(明文) -> AES-GCM 加密 -> SHA-256(密文)
// 同时被 Web Worker 和 Node 测试复用，不依赖任何 DOM/Worker 全局。

export async function readBlob(blob, signal) {
  const reader = blob.stream().getReader();
  const parts = [];
  let size = 0;
  try {
    for (;;) {
      if (signal && signal.aborted) {
        try { await reader.cancel(); } catch (_) {}
        throw new DOMException('read aborted', 'AbortError');
      }
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
      size += value.byteLength;
    }
  } finally {
    try { reader.releaseLock(); } catch (_) {}
  }
  const out = new Uint8Array(size);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
}

export async function processChunk(blob, cryptoKey, index, signal) {
  const data = await readBlob(blob, signal);
  if (signal && signal.aborted) throw new DOMException('aborted', 'AbortError');
  const plainHash = await crypto.subtle.digest('SHA-256', data);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
  const cipherHash = await crypto.subtle.digest('SHA-256', cipher);
  return { index, iv: iv.buffer, cipher, plainHash, cipherHash };
}

export async function decryptChunk(record, cryptoKey) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(record.iv) },
    cryptoKey,
    record.cipher
  );
  return plain;
}

// 最终文件哈希 = SHA-256(按分片序号顺序拼接的各分片明文哈希)
export async function finalFileHash(orderedPlainHashes) {
  const total = orderedPlainHashes.reduce((n, h) => n + h.byteLength, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const h of orderedPlainHashes) { buf.set(new Uint8Array(h), off); off += h.byteLength; }
  return crypto.subtle.digest('SHA-256', buf);
}

export function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
