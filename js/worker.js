// 加密流水线 Worker：分片读取(Streams API) → SHA-256 分片哈希 → AES-GCM 分片加密 → IndexedDB 持久化
import {
  openDB, saveSession, getSession, putChunk, deleteSession,
} from './idb.js';

const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
const MAX_ENCRYPT_ATTEMPTS = 3;
const PROGRESS_INTERVAL_MS = 250;

// 控制标志：由主线程消息驱动
let ctl = { paused: false, cancelled: false };
let resumeWaiter = null;
let retryWaiter = null;
let busy = false;

self.onmessage = (e) => {
  const msg = e.data;
  switch (msg.type) {
    case 'start':
      if (!busy) runJob(msg.file, msg.sessionId, msg.config || {});
      break;
    case 'pause':
      ctl.paused = true;
      break;
    case 'resume':
      ctl.paused = false;
      if (resumeWaiter) { resumeWaiter(); resumeWaiter = null; }
      break;
    case 'cancel':
      ctl.cancelled = true;
      ctl.paused = false;
      if (resumeWaiter) { resumeWaiter(); resumeWaiter = null; }
      if (retryWaiter) { retryWaiter(false); retryWaiter = null; }
      break;
    case 'retry':
      if (retryWaiter) { retryWaiter(true); retryWaiter = null; }
      break;
    case 'verify':
      if (!busy) runVerify(msg.file, msg.sessionId);
      break;
  }
};

function post(msg) { self.postMessage(msg); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function waitResume() {
  return new Promise((resolve) => { resumeWaiter = resolve; });
}

function waitRetryOrCancel() {
  return new Promise((resolve) => { retryWaiter = resolve; });
}

// Streams API 读取 Blob，文件被删除/移动时 read() 会 reject
async function readBlob(blob) {
  const reader = blob.stream().getReader();
  const parts = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
      size += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.byteLength; }
  return out;
}

async function sha256Hex(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Merkle 式根哈希：SHA-256(concat(各分片哈希))，保证分片顺序可校验
async function rootHashHex(chunkHashes) {
  const bytes = new Uint8Array(chunkHashes.length * 32);
  chunkHashes.forEach((hex, i) => {
    for (let j = 0; j < 32; j++) bytes[i * 32 + j] = parseInt(hex.substr(j * 2, 2), 16);
  });
  return sha256Hex(bytes);
}

// 加密失败自动重试（指数退避），仍失败则抛出让上层交给用户决策
async function encryptWithRetry(key, data, chunkIndex) {
  let lastErr = null;
  for (let attempt = 0; attempt < MAX_ENCRYPT_ATTEMPTS; attempt++) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
      const packet = new Uint8Array(12 + cipher.byteLength); // iv || ciphertext||tag
      packet.set(iv, 0);
      packet.set(new Uint8Array(cipher), 12);
      return packet;
    } catch (err) {
      lastErr = err;
      post({ type: 'log', level: 'warn', text: `分片 ${chunkIndex} 第 ${attempt + 1} 次加密失败：${err.message}` });
      await sleep(100 * 3 ** attempt);
    }
  }
  throw lastErr;
}

function isQuotaError(err) {
  return err && (err.name === 'QuotaExceededError' || err.name === 'NS_ERROR_DOM_QUOTA_REACHED');
}

async function runJob(file, sessionId, config) {
  busy = true;
  ctl = { paused: false, cancelled: false };
  let db;
  try {
    db = await openDB();
    let session;
    if (sessionId) {
      session = await getSession(db, sessionId);
      if (!session) { post({ type: 'error', fatal: true, message: '未找到可续传的历史任务' }); return; }
      if (session.fileName !== file.name || session.fileSize !== file.size || session.lastModified !== file.lastModified) {
        post({ type: 'error', fatal: true, message: '所选文件与历史任务不一致，无法续传' }); return;
      }
      post({ type: 'log', level: 'info', text: `断点续传：从分片 ${session.nextChunk}/${session.totalChunks} 继续` });
    } else {
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const keyJwk = await crypto.subtle.exportKey('jwk', key);
      session = {
        id: crypto.randomUUID(),
        fileName: file.name,
        fileSize: file.size,
        lastModified: file.lastModified,
        chunkSize: CHUNK_SIZE,
        totalChunks: Math.max(1, Math.ceil(file.size / CHUNK_SIZE)),
        nextChunk: 0,
        chunkHashes: [],
        keyJwk,
        persistCipher: config.persistCipher !== false,
        status: 'running',
        activeMs: 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    }

    const key = await crypto.subtle.importKey('jwk', session.keyJwk, { name: 'AES-GCM' }, false, ['encrypt']);
    session.status = 'running';
    session.updatedAt = Date.now();
    await saveSession(db, session);
    post({ type: 'state', state: 'running', session: publicSession(session) });

    let activeMs = session.activeMs || 0;
    let segStart = performance.now();
    let lastReportAt = performance.now();
    let lastReportBytes = Math.min(session.nextChunk * CHUNK_SIZE, file.size);
    let speedBps = 0;

    for (let i = session.nextChunk; i < session.totalChunks; i++) {
      if (ctl.cancelled) { await cancelCleanup(db, session); return; }

      if (ctl.paused) {
        activeMs += performance.now() - segStart;
        session.activeMs = activeMs;
        session.status = 'paused';
        session.updatedAt = Date.now();
        await saveSession(db, session);
        post({ type: 'state', state: 'paused', session: publicSession(session) });
        await waitResume();
        if (ctl.cancelled) { await cancelCleanup(db, session); return; }
        segStart = performance.now(); // 暂停时间不计入耗时，避免长时间运行漂移
        session.status = 'running';
        session.updatedAt = Date.now();
        await saveSession(db, session);
        post({ type: 'state', state: 'running', session: publicSession(session) });
      }

      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);

      // 1) 分片读取（文件被删除/移动会在这里抛错）
      let plain;
      try {
        plain = await readBlob(file.slice(start, end));
        if (plain.byteLength !== end - start) throw new Error(`读取长度异常（${plain.byteLength}/${end - start}）`);
      } catch (err) {
        session.status = 'error';
        session.updatedAt = Date.now();
        await saveSession(db, session);
        post({ type: 'error', fatal: false, retriable: true, chunkIndex: i, message: `分片 ${i} 读取失败：${err.message}（文件可能已被删除、移动或占用）` });
        const again = await waitRetryOrCancel();
        if (!again) { await cancelCleanup(db, session); return; }
        i -= 1;
        continue;
      }

      // 2) 分片哈希（明文 SHA-256）
      const hashHex = await sha256Hex(plain);

      // 3) 分片加密（自动重试，仍失败则等待用户重试/取消）
      let packet;
      try {
        packet = await encryptWithRetry(key, plain, i);
      } catch (err) {
        session.status = 'error';
        session.updatedAt = Date.now();
        await saveSession(db, session);
        post({ type: 'error', fatal: false, retriable: true, chunkIndex: i, message: `分片 ${i} 加密重试 ${MAX_ENCRYPT_ATTEMPTS} 次仍失败：${err.message}` });
        const again = await waitRetryOrCancel();
        if (!again) { await cancelCleanup(db, session); return; }
        i -= 1;
        continue;
      }

      // 4) 密文持久化（配额不足自动降级为不落盘模式）
      if (session.persistCipher) {
        try {
          await putChunk(db, session.id, i, packet.buffer);
        } catch (err) {
          if (isQuotaError(err)) {
            session.persistCipher = false;
            post({ type: 'degraded', reason: '存储配额不足，已降级：后续分片只计算哈希与加密校验，密文不再落盘，无法导出加密文件' });
          } else {
            throw err;
          }
        }
      }

      // 5) 记录状态（每个分片落盘一次，崩溃/刷新后可续传）
      session.chunkHashes[i] = hashHex;
      session.nextChunk = i + 1;
      session.updatedAt = Date.now();
      await saveSession(db, session);

      // 6) 节流进度上报；速度用 EWMA，时间全部基于 performance.now() 防漂移
      const now = performance.now();
      if (now - lastReportAt >= PROGRESS_INTERVAL_MS || i === session.totalChunks - 1) {
        const dt = (now - lastReportAt) / 1000;
        const inst = (end - lastReportBytes) / Math.max(dt, 1e-6);
        speedBps = speedBps > 0 ? 0.8 * speedBps + 0.2 * inst : inst;
        lastReportAt = now;
        lastReportBytes = end;
        post({
          type: 'progress',
          doneBytes: end,
          totalBytes: file.size,
          chunkIndex: i + 1,
          totalChunks: session.totalChunks,
          speedBps,
          etaSec: (file.size - end) / Math.max(speedBps, 1),
          activeMs: activeMs + (now - segStart),
        });
      }

      plain = null; // 显式释放，内存占用与文件大小解耦
      packet = null;
    }

    activeMs += performance.now() - segStart;
    const fileHash = await rootHashHex(session.chunkHashes);
    session.status = 'done';
    session.fileHash = fileHash;
    session.activeMs = activeMs;
    session.updatedAt = Date.now();
    await saveSession(db, session);
    post({ type: 'done', fileHash, activeMs, totalChunks: session.totalChunks, session: publicSession(session) });
  } catch (err) {
    post({ type: 'error', fatal: true, message: `任务异常终止：${err.message || err}` });
  } finally {
    busy = false;
  }
}

async function cancelCleanup(db, session) {
  session.status = 'cancelled';
  try { await deleteSession(db, session.id); } catch (_) { /* 忽略清理失败 */ }
  post({ type: 'state', state: 'cancelled' });
  post({ type: 'log', level: 'info', text: '任务已取消，本地状态已清理' });
}

// 校验：重新读取文件逐片哈希，与已存分片哈希逐一比对（顺序 + 内容双重校验）
async function runVerify(file, sessionId) {
  busy = true;
  ctl = { paused: false, cancelled: false };
  try {
    const db = await openDB();
    const session = await getSession(db, sessionId);
    if (!session || !session.chunkHashes || session.chunkHashes.length === 0) {
      post({ type: 'verifyResult', ok: false, message: '没有可校验的历史哈希' });
      return;
    }
    if (session.fileSize !== file.size) {
      post({ type: 'verifyResult', ok: false, message: '文件大小与记录不一致' });
      return;
    }
    post({ type: 'state', state: 'verifying' });
    for (let i = 0; i < session.totalChunks; i++) {
      if (ctl.cancelled) { post({ type: 'state', state: 'done' }); return; }
      const start = i * session.chunkSize;
      const end = Math.min(start + session.chunkSize, file.size);
      const plain = await readBlob(file.slice(start, end));
      const hashHex = await sha256Hex(plain);
      if (hashHex !== session.chunkHashes[i]) {
        post({ type: 'verifyResult', ok: false, mismatchAt: i, message: `分片 ${i} 哈希不匹配（文件可能已被修改）` });
        return;
      }
      post({ type: 'verifyProgress', doneBytes: end, totalBytes: file.size, chunkIndex: i + 1, totalChunks: session.totalChunks });
    }
    const fileHash = await rootHashHex(session.chunkHashes);
    post({ type: 'verifyResult', ok: true, fileHash, message: '全部分片哈希校验通过' });
  } catch (err) {
    post({ type: 'verifyResult', ok: false, message: `校验过程出错：${err.message}（文件可能已被删除）` });
  } finally {
    busy = false;
  }
}

function publicSession(s) {
  return {
    id: s.id,
    fileName: s.fileName,
    fileSize: s.fileSize,
    chunkSize: s.chunkSize,
    totalChunks: s.totalChunks,
    nextChunk: s.nextChunk,
    persistCipher: s.persistCipher,
    status: s.status,
  };
}

post({ type: 'ready' });
