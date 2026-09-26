// EncryptionEngine：环境无关的调度引擎。
// 依赖注入：storage（IndexedDB 或内存适配器）、processor（Worker 或直接调用）。
// 负责：分片调度与背压（内存控制）、暂停/继续/取消、失败重试、
// 配额降级、速度/ETA 估算（performance.now 单调时钟，长时间不漂移）。

import { finalFileHash, toHex } from './chunk-core.js';

export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
const MAX_IN_FLIGHT_LIMIT = 8;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class EncryptionEngine {
  /**
   * @param {object} opts
   * @param {{name:string,size:number,lastModified:number,slice:(a:number,b:number)=>Blob}} opts.file
   * @param {object} opts.storage  存储适配器（见 db.js / 测试内存适配器）
   * @param {object} opts.processor  { process(blob, keyHandle, index, signal) }
   * @param {(ev:object)=>void} opts.onEvent
   */
  constructor(opts) {
    this.file = opts.file;
    this.storage = opts.storage;
    this.processor = opts.processor;
    this.onEvent = opts.onEvent || (() => {});
    this.chunkSize = opts.chunkSize || CHUNK_SIZE;
    this.concurrency = opts.concurrency || 3;
    this.maxRetries = opts.maxRetries ?? 3;

    this.fileId = `${this.file.name}:${this.file.size}:${this.file.lastModified}`;
    this.totalChunks = Math.max(1, Math.ceil(this.file.size / this.chunkSize));

    this.state = 'idle'; // idle|running|pausing|paused|canceled|finished|error
    this.degraded = false; // 配额不足降级：只算哈希，不落密文
    this.doneChunks = new Map(); // index -> {plainHash, cipherHash}
    this.inFlight = new Map();   // index -> AbortController
    this.pending = [];
    this.retries = new Map();
    this.bytesDone = 0;
    this.ewmaSpeed = 0;          // bytes/s 指数加权平均
    this._lastTick = 0;
    this.keyHandle = null;       // { key: CryptoKey, jwk: object }
    this.manifest = null;
  }

  _emit(type, data = {}) { this.onEvent({ type, state: this.state, ...data }); }

  async init() {
    const existing = await this.storage.getManifest(this.fileId);
    if (existing && existing.totalChunks === this.totalChunks && existing.chunkSize === this.chunkSize) {
      this.manifest = existing;
      const key = await crypto.subtle.importKey('jwk', existing.jwk, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
      this.keyHandle = { key, jwk: existing.jwk };
      const saved = await this.storage.getChunks(this.fileId);
      for (const rec of saved) {
        if (rec.status === 'done' && rec.plainHash) {
          this.doneChunks.set(rec.index, { plainHash: rec.plainHash, cipherHash: rec.cipherHash });
          this.bytesDone += Math.min(this.chunkSize, this.file.size - rec.index * this.chunkSize);
        }
      }
      if (existing.degraded) this.degraded = true;
      this._emit('resumed-manifest', { doneChunks: this.doneChunks.size, totalChunks: this.totalChunks });
    } else {
      if (existing) await this._wipe();
      const jwk = await crypto.subtle.exportKey('jwk',
        await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
      this.keyHandle = { key, jwk };
      this.manifest = {
        fileId: this.fileId, name: this.file.name, size: this.file.size,
        lastModified: this.file.lastModified, chunkSize: this.chunkSize,
        totalChunks: this.totalChunks, jwk, degraded: false, createdAt: Date.now(),
      };
      await this.storage.putManifest(this.manifest);
    }

    // 配额预检：剩余空间放不下密文则直接降级（哈希校验仍完整）
    if (!this.degraded && this.storage.estimate) {
      try {
        const { quota, usage } = await this.storage.estimate();
        if (quota && quota - usage < this.file.size * 1.05) this._degrade('预估空间不足');
      } catch (_) { /* estimate 不可用时忽略 */ }
    }
    this._rebuildPending();
    return this;
  }

  _degrade(reason) {
    if (this.degraded) return;
    this.degraded = true;
    if (this.manifest) { this.manifest.degraded = true; this.storage.putManifest(this.manifest).catch(() => {}); }
    this._emit('degraded', { reason });
  }

  _rebuildPending() {
    this.pending = [];
    for (let i = 0; i < this.totalChunks; i++) {
      if (!this.doneChunks.has(i) && !this.inFlight.has(i)) this.pending.push(i);
    }
  }

  async start() {
    if (this.state === 'running') return;
    if (this.state === 'canceled' || this.state === 'finished') return;
    this.state = 'running';
    this._lastTick = performance.now();
    this._emit('state', {});
    this._pump();
  }

  pause() {
    if (this.state !== 'running') return;
    this.state = 'pausing'; // 在途分片允许完成并落盘，便于断点续传
    this._emit('state', {});
    this._checkPaused();
  }

  async resume() {
    if (this.state !== 'paused' && this.state !== 'error') return;
    this.retries.clear(); // 恢复后给予全新的重试额度
    this._rebuildPending();
    await this.start();
  }

  async cancel() {
    if (this.state === 'canceled') return;
    this.state = 'canceled';
    for (const c of this.inFlight.values()) c.abort();
    this.inFlight.clear();
    this.pending = [];
    await this._wipe();
    this._emit('state', {});
    this._emit('canceled', {});
  }

  async _wipe() {
    this.doneChunks.clear();
    this.bytesDone = 0;
    try { await this.storage.deleteChunks(this.fileId); } catch (_) {}
    try { await this.storage.deleteManifest(this.fileId); } catch (_) {}
  }

  _checkPaused() {
    if (this.state === 'pausing' && this.inFlight.size === 0) {
      this.state = 'paused';
      this._persistManifest();
      this._emit('state', {});
    }
  }

  _persistManifest() {
    if (!this.manifest) return;
    this.manifest.doneChunks = this.doneChunks.size;
    this.manifest.updatedAt = Date.now();
    this.storage.putManifest(this.manifest).catch(() => {});
  }

  _pump() {
    if (this.state !== 'running') return;
    while (this.inFlight.size < Math.min(this.concurrency, MAX_IN_FLIGHT_LIMIT) && this.pending.length) {
      const index = this.pending.shift();
      this._runChunk(index);
    }
    this._maybeFinish();
  }

  async _runChunk(index) {
    const controller = new AbortController();
    this.inFlight.set(index, controller);
    const start = index * this.chunkSize;
    const end = Math.min(start + this.chunkSize, this.file.size);
    try {
      const r = await this.processor.process(this.file.slice(start, end), this.keyHandle, index, controller.signal);
      if (this.state === 'canceled') return;
      await this._saveChunk(index, r);
      this.doneChunks.set(index, { plainHash: r.plainHash, cipherHash: r.cipherHash });
      this.retries.delete(index);
      this.bytesDone += end - start;
      this._updateSpeed(end - start);
      this._emit('chunk-done', { index, doneChunks: this.doneChunks.size, totalChunks: this.totalChunks });
      this._emit('progress', this._progress());
      if (this.doneChunks.size % 8 === 0) this._persistManifest();
    } catch (err) {
      if (this.state === 'canceled' || (err && err.name === 'AbortError')) {
        // 取消/中止：静默丢弃
      } else {
        const n = (this.retries.get(index) || 0) + 1;
        this.retries.set(index, n);
        if (n <= this.maxRetries) {
          this._emit('chunk-retry', { index, attempt: n, maxRetries: this.maxRetries, error: String(err && err.message || err) });
          await sleep(Math.min(400 * 2 ** (n - 1), 4000)); // 指数退避
          // 非终态都回队列，避免退避唤醒恰逢 pause/error 时分片丢失
          if (this.state !== 'canceled' && this.state !== 'finished') this.pending.unshift(index);
        } else {
          // 重试耗尽（典型场景：文件被删除/读取中断）-> 进入 error，可稍后 resume
          this.state = 'error';
          this.lastError = String(err && err.message || err);
          this._persistManifest();
          this._emit('error', { index, error: this.lastError });
        }
      }
    } finally {
      this.inFlight.delete(index);
      if (this.state === 'running') this._pump();
      else { this._checkPaused(); this._maybeFinish(); }
    }
  }

  async _saveChunk(index, r) {
    const base = { fileId: this.fileId, index, plainHash: r.plainHash, cipherHash: r.cipherHash, status: 'done' };
    if (this.degraded) {
      await this.storage.putChunk(this.fileId, { ...base, noCipher: true });
      return;
    }
    try {
      await this.storage.putChunk(this.fileId, { ...base, iv: r.iv, cipher: r.cipher });
    } catch (err) {
      if (err && (err.name === 'QuotaExceededError' || /quota/i.test(String(err.message)))) {
        this._degrade('IndexedDB 配额不足，切换为仅哈希模式');
        await this.storage.putChunk(this.fileId, { ...base, noCipher: true });
      } else {
        throw err;
      }
    }
  }

  _updateSpeed(bytes) {
    const now = performance.now(); // 单调时钟，不受系统时间调整影响
    const dt = (now - this._lastTick) / 1000;
    this._lastTick = now;
    if (dt <= 0) return;
    const inst = bytes / dt;
    this.ewmaSpeed = this.ewmaSpeed ? 0.25 * inst + 0.75 * this.ewmaSpeed : inst;
  }

  _progress() {
    const remaining = this.file.size - this.bytesDone;
    return {
      bytesDone: this.bytesDone,
      totalBytes: this.file.size,
      percent: (this.bytesDone / this.file.size) * 100,
      speed: this.ewmaSpeed,
      etaSeconds: this.ewmaSpeed > 0 ? remaining / this.ewmaSpeed : Infinity,
      doneChunks: this.doneChunks.size,
      totalChunks: this.totalChunks,
      degraded: this.degraded,
    };
  }

  async _maybeFinish() {
    if (this.state !== 'running' && this.state !== 'pausing') return;
    if (this.doneChunks.size !== this.totalChunks || this.inFlight.size !== 0) return;
    const ordered = [];
    for (let i = 0; i < this.totalChunks; i++) ordered.push(this.doneChunks.get(i).plainHash);
    const hash = await finalFileHash(ordered);
    this.state = 'finished';
    this._persistManifest();
    this._emit('progress', this._progress());
    this._emit('finished', { fileHash: toHex(hash), degraded: this.degraded });
  }
}
