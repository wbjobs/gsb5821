// Node 验收测试：复用与浏览器完全相同的 engine.js / chunk-core.js。
// 运行：node test/verify.mjs
import { EncryptionEngine } from '../js/engine.js';
import { processChunk, decryptChunk, toHex } from '../js/chunk-core.js';

const CHUNK = 8 * 1024 * 1024;
let passed = 0, failed = 0;
const ok = (cond, name) => { if (cond) { passed++; console.log(`  ✔ ${name}`); } else { failed++; console.error(`  ✘ ${name}`); } };

// ---------- 测试替身 ----------
class MemStorage {
  constructor({ quotaBytes = Infinity } = {}) { this.manifests = new Map(); this.chunks = new Map(); this.quotaBytes = quotaBytes; this.used = 0; }
  async estimate() { return { quota: this.quotaBytes, usage: this.used }; }
  async getManifest(id) { return this.manifests.get(id); }
  async putManifest(m) { this.manifests.set(m.fileId, structuredCloneSafe(m)); }
  async deleteManifest(id) { this.manifests.delete(id); }
  async putChunk(fileId, rec) {
    const size = rec.cipher ? rec.cipher.byteLength : 0;
    if (this.used + size > this.quotaBytes) { const e = new Error('quota exceeded'); e.name = 'QuotaExceededError'; throw e; }
    this.used += size;
    this.chunks.set(`${fileId}:${rec.index}`, { ...rec });
  }
  async getChunks(fileId) {
    return [...this.chunks.entries()].filter(([k]) => k.startsWith(fileId + ':')).map(([, v]) => v);
  }
  async deleteChunks(fileId) { for (const k of [...this.chunks.keys()]) if (k.startsWith(fileId + ':')) this.chunks.delete(k); }
}
const structuredCloneSafe = (o) => JSON.parse(JSON.stringify(o));

class FakeFile {
  constructor(name, buf) { this.name = name; this.size = buf.byteLength; this.lastModified = 123; this._buf = buf; this.deleted = false; }
  slice(a, b) {
    if (this.deleted) throw new Error('file has been deleted');
    return new Blob([this._buf.subarray(a, b)]);
  }
}

const directProcessor = {
  async process(blob, keyHandle, index, signal) { return processChunk(blob, keyHandle.key, index, signal); },
};

function makeFlakyProcessor(failTimes, base = directProcessor) {
  const fails = new Map();
  return {
    async process(blob, keyHandle, index, signal) {
      const n = fails.get(index) || 0;
      if (n < failTimes) { fails.set(index, n + 1); throw new Error('injected crypto failure'); }
      return base.process(blob, keyHandle, index, signal);
    },
  };
}

function makeSlowProcessor(maxMs, base = directProcessor) {
  return {
    async process(blob, keyHandle, index, signal) {
      await new Promise((r) => setTimeout(r, Math.random() * maxMs)); // 随机延迟 -> 乱序完成
      return base.process(blob, keyHandle, index, signal);
    },
  };
}

function makePatternBuffer(size) {
  const buf = Buffer.alloc(size);
  for (let i = 0; i < size; i += 4096) buf.writeUInt32LE(i & 0xffffffff, i % buf.length);
  return buf;
}

// 独立参考实现：不经过 engine/chunk-core 的最终哈希
async function referenceFileHash(buf, chunkSize) {
  const hashes = [];
  for (let off = 0; off < Math.max(1, buf.byteLength); off += chunkSize) {
    const end = Math.min(off + chunkSize, buf.byteLength);
    if (off >= end) break;
    hashes.push(Buffer.from(await crypto.subtle.digest('SHA-256', buf.subarray(off, end))));
  }
  return toHex(await crypto.subtle.digest('SHA-256', Buffer.concat(hashes)));
}

function runEngine(engine, events = {}) {
  return new Promise((resolve, reject) => {
    const orig = engine.onEvent;
    engine.onEvent = (ev) => {
      orig(ev);
      if (events[ev.type]) events[ev.type](ev);
      if (ev.type === 'finished') resolve(ev);
      if (ev.type === 'error') { /* 不 reject，由测试决定 */ }
    };
  });
}

async function newEngine(file, storage, processor, opts = {}) {
  const eng = new EncryptionEngine({ file, storage, processor, concurrency: opts.concurrency || 3, onEvent: opts.onEvent || (() => {}), ...opts.extra });
  await eng.init();
  return eng;
}

// ---------- 用例 ----------
async function testFullRun(sizeMB, keepCipher) {
  console.log(`\n[1] 完整运行 ${sizeMB}MB（${keepCipher ? '保留密文' : '配额受限->降级仅哈希'}）`);
  const buf = makePatternBuffer(sizeMB * 1024 * 1024);
  const file = new FakeFile('big.bin', buf);
  const storage = new MemStorage({ quotaBytes: keepCipher ? Infinity : 1024 }); // 1KB 配额 -> 必降级
  let degraded = false;
  const eng = await newEngine(file, storage, directProcessor, { onEvent: (ev) => { if (ev.type === 'degraded') degraded = true; } });
  const memBefore = process.memoryUsage().heapUsed;
  const t0 = performance.now();
  const doneP = runEngine(eng);
  await eng.start();
  const fin = await doneP;
  const secs = (performance.now() - t0) / 1000;
  global.gc && global.gc();
  const memGrowth = (process.memoryUsage().heapUsed - memBefore) / 1024 / 1024;
  const expected = await referenceFileHash(buf, CHUNK);
  ok(fin.fileHash === expected, `最终哈希正确 (${fin.fileHash.slice(0, 16)}…)`);
  ok(!keepCipher ? degraded : !degraded, keepCipher ? '未误触发降级' : '配额不足自动降级');
  ok(memGrowth < 300, `内存有界（堆增长 ${memGrowth.toFixed(0)}MB << 文件 ${sizeMB}MB）`);
  console.log(`  ⏱ ${secs.toFixed(1)}s · ${(sizeMB / secs).toFixed(0)} MB/s`);
  return { buf, expected };
}

async function testDecryptRoundtrip() {
  console.log('\n[2] 密文可解密且分片顺序正确（96MB）');
  const buf = makePatternBuffer(96 * 1024 * 1024);
  const file = new FakeFile('rt.bin', buf);
  const storage = new MemStorage();
  const eng = await newEngine(file, storage, makeSlowProcessor(30)); // 乱序完成
  const doneP = runEngine(eng);
  await eng.start();
  await doneP;
  const key = eng.keyHandle.key;
  let orderOk = true, decryptOk = true;
  for (let i = 0; i < eng.totalChunks; i++) {
    const rec = await storage.getChunks(file.name ? eng.fileId : eng.fileId).then((a) => a.find((r) => r.index === i));
    if (!rec || !rec.cipher) { decryptOk = false; break; }
    const plain = await decryptChunk(rec, key);
    const start = i * CHUNK, end = Math.min(start + CHUNK, buf.byteLength);
    if (!Buffer.from(plain).equals(buf.subarray(start, end))) decryptOk = false;
    const ph = toHex(await crypto.subtle.digest('SHA-256', plain));
    if (ph !== toHex(rec.plainHash)) orderOk = false;
  }
  ok(decryptOk, '每个分片 AES-GCM 解密回原文');
  ok(orderOk, '乱序完成后各分片哈希与明文一一对应');
}

async function testPauseResume() {
  console.log('\n[3] 暂停后继续，最终哈希不变（128MB）');
  const buf = makePatternBuffer(128 * 1024 * 1024);
  const expected = await referenceFileHash(buf, CHUNK);
  const file = new FakeFile('pr.bin', buf);
  const storage = new MemStorage();
  const eng = await newEngine(file, storage, makeSlowProcessor(10));
  let paused = false;
  const doneP = runEngine(eng, {
    'chunk-done': () => {
      if (!paused && eng.doneChunks.size >= Math.floor(eng.totalChunks / 3)) { paused = true; eng.pause(); }
    },
  });
  await eng.start();
  await new Promise((r) => {
    const t = setInterval(() => { if (eng.state === 'paused') { clearInterval(t); r(); } }, 20);
  });
  const doneAtPause = eng.doneChunks.size;
  ok(doneAtPause > 0 && doneAtPause < eng.totalChunks, `在 ${doneAtPause}/${eng.totalChunks} 分片处暂停`);
  await eng.resume();
  const fin = await doneP;
  ok(fin.fileHash === expected, '暂停-继续后最终哈希与一次性运行一致');
}

async function testResumeAcrossReload() {
  console.log('\n[4] 模拟页面刷新后的断点续传（96MB）');
  const buf = makePatternBuffer(96 * 1024 * 1024);
  const expected = await referenceFileHash(buf, CHUNK);
  const file = new FakeFile('reload.bin', buf);
  const storage = new MemStorage();
  const eng1 = await newEngine(file, storage, makeSlowProcessor(5));
  const halfDone = new Promise((r) => {
    const t = setInterval(() => { if (eng1.doneChunks.size >= eng1.totalChunks / 2) { clearInterval(t); r(); } }, 10);
  });
  eng1.onEvent = () => {};
  eng1.start();
  await halfDone;
  eng1.pause();
  await new Promise((r) => { const t = setInterval(() => { if (eng1.state === 'paused') { clearInterval(t); r(); } }, 10); });
  const doneBefore = eng1.doneChunks.size;
  // 模拟刷新：新引擎 + 同一 storage + 同一文件
  const eng2 = await newEngine(file, storage, directProcessor);
  ok(eng2.doneChunks.size === doneBefore, `刷新后恢复 ${eng2.doneChunks.size} 个已完成分片`);
  const doneP = runEngine(eng2);
  await eng2.start();
  const fin = await doneP;
  ok(fin.fileHash === expected, '断点续传最终哈希正确');
}

async function testCancel() {
  console.log('\n[5] 取消立即停止并清理（256MB）');
  const buf = makePatternBuffer(256 * 1024 * 1024);
  const file = new FakeFile('cancel.bin', buf);
  const storage = new MemStorage();
  const eng = await newEngine(file, storage, makeSlowProcessor(50));
  eng.onEvent = () => {};
  eng.start();
  await new Promise((r) => setTimeout(r, 150));
  const t0 = performance.now();
  await eng.cancel();
  const stopMs = performance.now() - t0;
  const doneAtCancel = eng.doneChunks.size;
  await new Promise((r) => setTimeout(r, 300));
  ok(eng.state === 'canceled', '状态为 canceled');
  ok(stopMs < 500, `取消即时生效（${stopMs.toFixed(0)}ms）`);
  ok(eng.doneChunks.size <= doneAtCancel + eng.concurrency, '取消后无新分片完成');
  ok((await storage.getChunks(eng.fileId)).length === 0 && !(await storage.getManifest(eng.fileId)), 'IndexedDB 临时数据已清理');
}

async function testRetry() {
  console.log('\n[6] 加密失败自动重试（64MB，每片先失败2次）');
  const buf = makePatternBuffer(64 * 1024 * 1024);
  const expected = await referenceFileHash(buf, CHUNK);
  const file = new FakeFile('retry.bin', buf);
  const storage = new MemStorage();
  let retries = 0;
  const eng = await newEngine(file, storage, makeFlakyProcessor(2), { onEvent: (ev) => { if (ev.type === 'chunk-retry') retries++; } });
  const doneP = runEngine(eng);
  await eng.start();
  const fin = await doneP;
  ok(retries >= eng.totalChunks * 2, `发生 ${retries} 次重试`);
  ok(fin.fileHash === expected, '重试后最终哈希仍正确');
}

async function testFileDeleted() {
  console.log('\n[7] 文件被删除 -> 重试耗尽进入 error，可恢复（64MB）');
  const buf = makePatternBuffer(64 * 1024 * 1024);
  const file = new FakeFile('gone.bin', buf);
  const storage = new MemStorage();
  let errEv = null, restored = false;
  const eng = await newEngine(file, storage, makeSlowProcessor(120), { onEvent: (ev) => {
    if (ev.type === 'error') errEv = ev;
    if (ev.type === 'chunk-done' && !restored) file.deleted = true; // 首个分片完成后模拟文件被删除
  } });
  eng.start();
  await new Promise((r) => { const t = setInterval(() => { if (eng.state === 'error') { clearInterval(t); r(); } }, 50); });
  ok(!!errEv, `报错并自动暂停：${errEv && errEv.error}`);
  ok(eng.doneChunks.size > 0, `已完成的 ${eng.doneChunks.size} 个分片进度保留`);
  file.deleted = false; restored = true; // 文件恢复
  const doneP = runEngine(eng);
  await eng.resume();
  const fin = await doneP;
  ok(fin.fileHash === await referenceFileHash(buf, CHUNK), '文件恢复后继续，最终哈希正确');
}

async function testQuotaMidRun() {
  console.log('\n[8] 运行中途配额耗尽 -> 动态降级（64MB）');
  const buf = makePatternBuffer(64 * 1024 * 1024);
  const expected = await referenceFileHash(buf, CHUNK);
  const file = new FakeFile('quota.bin', buf);
  const storage = new MemStorage({ quotaBytes: 20 * 1024 * 1024 }); // 只够 ~2 个分片
  let degraded = false;
  const eng = await newEngine(file, storage, directProcessor, { onEvent: (ev) => { if (ev.type === 'degraded') degraded = true; } });
  const doneP = runEngine(eng);
  await eng.start();
  const fin = await doneP;
  ok(degraded && fin.degraded, 'QuotaExceededError 触发动态降级');
  ok(fin.fileHash === expected, '降级后最终哈希仍正确');
}

// ---------- 执行 ----------
const only1G = process.argv.includes('--1g');
await testFullRun(only1G ? 1024 : 256, false);
await testDecryptRoundtrip();
await testPauseResume();
await testResumeAcrossReload();
await testCancel();
await testRetry();
await testFileDeleted();
await testQuotaMidRun();

console.log(`\n结果：${passed} 通过，${failed} 失败`);
process.exit(failed ? 1 : 0);
