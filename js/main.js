// 主线程：只做状态管理与 UI，所有重计算在 Worker。进度刷新按 rAF 节流，保证 60fps。
import { EncryptionEngine } from './engine.js';
import { IdbStorage } from './db.js';

const $ = (id) => document.getElementById(id);
const fileInput = $('file'), btnStart = $('btnStart'), btnPause = $('btnPause'),
      btnResume = $('btnResume'), btnCancel = $('btnCancel');
const bar = $('bar'), pct = $('pct'), speedEl = $('speed'), etaEl = $('eta'),
      stateEl = $('state'), fpsEl = $('fps'), quotaEl = $('quota'),
      chunkGrid = $('chunkGrid'), logEl = $('log'), hashEl = $('hash'), degradeEl = $('degrade');

let engine = null;
let uiDirty = false;
let lastProgress = null;
const chunkState = new Map(); // index -> 'pending'|'active'|'done'|'retry'

// ---------- Worker 处理器（背压由引擎的并发上限保证，内存有界） ----------
class WorkerProcessor {
  constructor() {
    this.worker = new Worker('./js/worker.js', { type: 'module' });
    this.pending = new Map();
    this.seq = 0;
    this.keyJwk = null;
    this.worker.onmessage = (e) => {
      const m = e.data;
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (m.type === 'done') p.resolve({ iv: m.iv, cipher: m.cipher, plainHash: m.plainHash, cipherHash: m.cipherHash });
      else { const err = new Error(m.error); err.name = m.name || 'Error'; p.reject(err); }
    };
  }
  process(blob, keyHandle, index, signal) {
    if (this.keyJwk !== keyHandle.jwk) {
      this.worker.postMessage({ type: 'setKey', jwk: keyHandle.jwk });
      this.keyJwk = keyHandle.jwk;
    }
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const onAbort = () => {
        this.worker.postMessage({ type: 'abort', id });
        const p = this.pending.get(id);
        if (p) { this.pending.delete(id); p.reject(new DOMException('aborted', 'AbortError')); }
      };
      if (signal.aborted) return onAbort();
      signal.addEventListener('abort', onAbort, { once: true });
      this.worker.postMessage({ type: 'process', id, blob, index });
    });
  }
}

// ---------- 日志 / 格式化 ----------
function log(msg, cls = '') {
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}.${String(performance.now() % 1000 | 0).padStart(3, '0')}] ${msg}`;
  logEl.prepend(line);
  while (logEl.childNodes.length > 200) logEl.lastChild.remove();
}
const fmtBytes = (n) => n >= 1 << 30 ? (n / (1 << 30)).toFixed(2) + ' GB' : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : (n / 1024).toFixed(0) + ' KB';
const fmtSpeed = (b) => fmtBytes(b) + '/s';
const fmtEta = (s) => !isFinite(s) ? '--:--' : s >= 3600 ? `${(s / 3600) | 0}h${((s % 3600) / 60) | 0}m` : s >= 60 ? `${(s / 60) | 0}m${(s % 60) | 0}s` : `${s | 0}s`;

// ---------- 性能监控：PerformanceObserver(longtask) + rAF FPS ----------
let longtasks = 0;
try {
  new PerformanceObserver((list) => {
    longtasks += list.getEntries().length;
  }).observe({ entryTypes: ['longtask'] });
} catch (_) { /* 旧浏览器无 longtask */ }

let frames = 0, lastFpsTick = performance.now();
(function fpsLoop(now) {
  frames++;
  if (now - lastFpsTick >= 1000) {
    fpsEl.textContent = `FPS ${frames} · 长任务 ${longtasks}`;
    if (longtasks > 8 && engine && engine.concurrency > 1) {
      engine.concurrency--; // 主线程吃紧时自动降并发，保帧率
      log(`检测到长任务过多，并发降至 ${engine.concurrency}`, 'warn');
    }
    frames = 0; longtasks = 0; lastFpsTick = now;
  }
  requestAnimationFrame(fpsLoop);
})(performance.now());

// ---------- UI 刷新（rAF 节流，避免高频 progress 事件阻塞渲染） ----------
function renderLoop() {
  if (uiDirty && lastProgress) {
    uiDirty = false;
    const p = lastProgress;
    bar.style.width = p.percent.toFixed(2) + '%';
    pct.textContent = p.percent.toFixed(1) + '%';
    speedEl.textContent = fmtSpeed(p.speed);
    etaEl.textContent = fmtEta(p.etaSeconds);
    degradeEl.hidden = !p.degraded;
  }
  requestAnimationFrame(renderLoop);
}
requestAnimationFrame(renderLoop);

function renderChunks() {
  if (!engine) return;
  const n = engine.totalChunks;
  if (chunkGrid.childElementCount !== n) {
    chunkGrid.textContent = '';
    const frag = document.createDocumentFragment();
    for (let i = 0; i < n; i++) {
      const cell = document.createElement('i');
      cell.dataset.s = chunkState.get(i) || 'pending';
      frag.appendChild(cell);
    }
    chunkGrid.appendChild(frag);
  } else {
    const cells = chunkGrid.children;
    for (let i = 0; i < n; i++) {
      const s = chunkState.get(i) || 'pending';
      if (cells[i].dataset.s !== s) cells[i].dataset.s = s;
    }
  }
}

function setState(s) {
  stateEl.textContent = { idle: '空闲', running: '运行中', pausing: '暂停中…', paused: '已暂停', canceled: '已取消', finished: '已完成', error: '错误' }[s] || s;
  btnStart.disabled = !(s === 'idle');
  btnPause.disabled = s !== 'running';
  btnResume.disabled = !(s === 'paused' || s === 'error');
  btnCancel.disabled = !(s === 'running' || s === 'pausing' || s === 'paused' || s === 'error');
}

async function refreshQuota() {
  try {
    const { quota, usage } = await navigator.storage.estimate();
    quotaEl.textContent = `存储 ${fmtBytes(usage)} / ${fmtBytes(quota)}`;
  } catch (_) { quotaEl.textContent = ''; }
}
setInterval(refreshQuota, 5000);

// ---------- 引擎事件 ----------
function onEvent(ev) {
  switch (ev.type) {
    case 'state': setState(engine.state); break;
    case 'progress': lastProgress = ev; uiDirty = true; break;
    case 'chunk-done':
      chunkState.set(ev.index, 'done'); renderChunks(); break;
    case 'chunk-retry':
      chunkState.set(ev.index, 'retry'); renderChunks();
      log(`分片 #${ev.index} 失败，第 ${ev.attempt}/${ev.maxRetries} 次重试：${ev.error}`, 'warn'); break;
    case 'degraded':
      degradeEl.hidden = false;
      log(`降级：${ev.reason}（仅计算哈希，不保存密文）`, 'warn');
      refreshQuota(); break;
    case 'resumed-manifest':
      if (ev.doneChunks > 0) log(`发现未完成任务：${ev.doneChunks}/${ev.totalChunks} 分片已完成，可断点续传`);
      for (const [i] of engine.doneChunks) chunkState.set(i, 'done');
      renderChunks(); break;
    case 'error':
      log(`错误（分片 #${ev.index}）：${ev.error}。文件可能被删除或读取中断，可点“继续”重试。`, 'err'); break;
    case 'finished':
      hashEl.textContent = `SHA-256(分片哈希链) = ${ev.fileHash}`;
      log(`完成！最终哈希 ${ev.fileHash}`, 'ok');
      refreshQuota(); break;
    case 'canceled':
      log('已取消，临时数据已清理'); hashEl.textContent = ''; break;
  }
}

// ---------- 交互 ----------
let currentFile = null;
fileInput.onchange = async () => {
  currentFile = fileInput.files[0];
  if (!currentFile) return;
  if (engine) await engine.cancel();
  chunkState.clear(); chunkGrid.textContent = ''; hashEl.textContent = '';
  engine = new EncryptionEngine({
    file: currentFile,
    storage: new IdbStorage(),
    processor: new WorkerProcessor(),
    concurrency: 3,
    onEvent,
  });
  await engine.init();
  for (const [i] of engine.doneChunks) chunkState.set(i, 'done');
  renderChunks();
  setState(engine.doneChunks.size ? 'paused' : 'idle');
  log(`已选择 ${currentFile.name}（${fmtBytes(currentFile.size)}，${engine.totalChunks} 个分片）`);
  refreshQuota();
};

btnStart.onclick = () => engine && engine.start();
btnPause.onclick = () => engine && engine.pause();
btnResume.onclick = () => engine && engine.resume();
btnCancel.onclick = () => {
  if (!engine) return;
  engine.cancel();
  chunkState.clear(); renderChunks();
  lastProgress = { percent: 0, speed: 0, etaSeconds: Infinity, degraded: false };
  uiDirty = true;
  setState('idle');
};
