// 主线程：UI 状态机 + 进度展示 + PerformanceObserver 长任务监控 + 导出
import {
  openDB, findSessionByFile, getSession, deleteSession, getChunk, listSessions,
} from './idb.js';

const worker = new Worker('./js/worker.js', { type: 'module' });

const $ = (id) => document.getElementById(id);
const els = {
  dropzone: $('dropzone'),
  fileInput: $('fileInput'),
  fileInfo: $('fileInfo'),
  resumeBanner: $('resumeBanner'),
  btnStart: $('btnStart'),
  btnPause: $('btnPause'),
  btnResume: $('btnResume'),
  btnCancel: $('btnCancel'),
  btnRetry: $('btnRetry'),
  btnVerify: $('btnVerify'),
  btnExport: $('btnExport'),
  btnExportKey: $('btnExportKey'),
  progressBar: $('progressBar'),
  progressText: $('progressText'),
  statSpeed: $('statSpeed'),
  statEta: $('statEta'),
  statElapsed: $('statElapsed'),
  statChunks: $('statChunks'),
  statStatus: $('statStatus'),
  statFps: $('statFps'),
  statLongtask: $('statLongtask'),
  statHeap: $('statHeap'),
  statQuota: $('statQuota'),
  hashResult: $('hashResult'),
  errorBox: $('errorBox'),
  log: $('log'),
};

let currentFile = null;
let pendingSession = null; // 检测到的可续传会话
let activeSessionId = null;
let appState = 'idle'; // idle | running | paused | error | done | cancelled | verifying

// ---------- 工具 ----------
function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let u = -1;
  do { v /= 1024; u += 1; } while (v >= 1024 && u < units.length - 1);
  return `${v.toFixed(2)} ${units[u]}`;
}

function fmtDuration(sec) {
  if (!Number.isFinite(sec) || sec < 0) return '--';
  const s = Math.round(sec);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h > 0 ? `${h}时${m}分${r}秒` : m > 0 ? `${m}分${r}秒` : `${r}秒`;
}

function log(text, level = 'info') {
  const line = document.createElement('div');
  line.className = `log-line log-${level}`;
  line.textContent = `[${new Date().toLocaleTimeString('zh-CN', { hour12: false })}] ${text}`;
  els.log.prepend(line);
  while (els.log.children.length > 80) els.log.lastChild.remove();
}

function showError(msg) {
  els.errorBox.textContent = msg;
  els.errorBox.hidden = !msg;
}

function setState(state) {
  appState = state;
  els.statStatus.textContent = {
    idle: '空闲', running: '运行中', paused: '已暂停', error: '出错',
    done: '已完成', cancelled: '已取消', verifying: '校验中',
  }[state] || state;
  const hasFile = !!currentFile;
  els.btnStart.disabled = !(hasFile && (appState === 'idle' || appState === 'cancelled' || appState === 'done'));
  els.btnPause.disabled = appState !== 'running';
  els.btnResume.disabled = appState !== 'paused';
  els.btnCancel.disabled = !(appState === 'running' || appState === 'paused' || appState === 'error' || appState === 'verifying');
  els.btnRetry.disabled = appState !== 'error';
  els.btnVerify.disabled = !(hasFile && (appState === 'done' || appState === 'paused'));
  els.btnExport.disabled = appState !== 'done';
  els.btnExportKey.disabled = appState !== 'done';
}

// ---------- 文件选择 ----------
els.dropzone.addEventListener('click', () => els.fileInput.click());
els.dropzone.addEventListener('dragover', (e) => { e.preventDefault(); els.dropzone.classList.add('drag'); });
els.dropzone.addEventListener('dragleave', () => els.dropzone.classList.remove('drag'));
els.dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  els.dropzone.classList.remove('drag');
  if (e.dataTransfer.files.length) pickFile(e.dataTransfer.files[0]);
});
els.fileInput.addEventListener('change', () => {
  if (els.fileInput.files.length) pickFile(els.fileInput.files[0]);
});

async function pickFile(file) {
  currentFile = file;
  pendingSession = null;
  els.hashResult.textContent = '';
  showError('');
  els.fileInfo.textContent = `${file.name} · ${fmtBytes(file.size)} · 修改于 ${new Date(file.lastModified).toLocaleString('zh-CN')}`;
  if (file.size < 1024 * 1024 * 1024) {
    log('提示：文件小于 1GB，仍可处理（建议用 1GB+ 文件验证验收标准）', 'warn');
  }
  try {
    const db = await openDB();
    const hit = await findSessionByFile(db, file.name, file.size, file.lastModified);
    if (hit) {
      pendingSession = hit;
      els.resumeBanner.textContent = `检测到未完成任务：已完成 ${hit.nextChunk}/${hit.totalChunks} 个分片，点击「开始」将断点续传`;
      els.resumeBanner.hidden = false;
      log(`发现可续传会话（进度 ${hit.nextChunk}/${hit.totalChunks}）`);
    } else {
      els.resumeBanner.hidden = true;
    }
  } catch (err) {
    log(`读取历史任务失败：${err.message}`, 'warn');
  }
  setState('idle');
}

// ---------- 配额预检 ----------
async function checkQuota(needBytes) {
  if (!navigator.storage || !navigator.storage.estimate) return { persistCipher: true };
  const { quota = 0, usage = 0 } = await navigator.storage.estimate();
  const free = quota - usage;
  els.statQuota.textContent = `${fmtBytes(usage)} / ${fmtBytes(quota)}`;
  if (free < needBytes * 1.05) {
    const ok = window.confirm(
      `存储配额不足（剩余约 ${fmtBytes(free)}，密文需要约 ${fmtBytes(needBytes)}）。\n`
      + '确定：降级模式（只做哈希+加密校验，密文不落盘，不可导出）\n取消：放弃本次任务',
    );
    if (!ok) return null;
    log('配额不足，进入降级模式：密文不落盘', 'warn');
    return { persistCipher: false };
  }
  return { persistCipher: true };
}

// ---------- 按钮 ----------
els.btnStart.addEventListener('click', async () => {
  if (!currentFile) return;
  showError('');
  const resume = pendingSession && pendingSession.id;
  let config = { persistCipher: true };
  if (!resume) {
    const decision = await checkQuota(currentFile.size);
    if (!decision) return;
    config = decision;
  } else {
    config = { persistCipher: pendingSession.persistCipher };
  }
  activeSessionId = resume || null;
  worker.postMessage({ type: 'start', file: currentFile, sessionId: resume || undefined, config });
  log(resume ? '发送续传指令' : '发送开始指令');
});

els.btnPause.addEventListener('click', () => worker.postMessage({ type: 'pause' }));
els.btnResume.addEventListener('click', () => worker.postMessage({ type: 'resume' }));
els.btnCancel.addEventListener('click', () => {
  worker.postMessage({ type: 'cancel' });
  pendingSession = null;
  activeSessionId = null;
});
els.btnRetry.addEventListener('click', () => {
  showError('');
  worker.postMessage({ type: 'retry' });
  setState('running');
});
els.btnVerify.addEventListener('click', async () => {
  if (!currentFile || !activeSessionId) return;
  showError('');
  worker.postMessage({ type: 'verify', file: currentFile, sessionId: activeSessionId });
});

// 导出加密文件（File System Access API，流式写出，内存恒定）
els.btnExport.addEventListener('click', async () => {
  if (!activeSessionId || !window.showSaveFilePicker) {
    log('当前浏览器不支持 File System Access API，无法导出', 'error');
    return;
  }
  try {
    const db = await openDB();
    const session = await getSession(db, activeSessionId);
    if (!session || !session.persistCipher) {
      log('该任务处于降级模式，密文未落盘，无法导出', 'error');
      return;
    }
    const handle = await window.showSaveFilePicker({ suggestedName: `${session.fileName}.enc` });
    const writable = await handle.createWritable();
    for (let i = 0; i < session.totalChunks; i++) {
      const data = await getChunk(db, session.id, i);
      if (!data) throw new Error(`缺少分片 ${i}，导出中止`);
      await writable.write(data);
      els.progressText.textContent = `导出中 ${i + 1}/${session.totalChunks}`;
    }
    await writable.close();
    log(`加密文件导出完成（格式：每分片 iv(12B) || 密文||tag）`);
  } catch (err) {
    if (err.name !== 'AbortError') log(`导出失败：${err.message}`, 'error');
  }
});

// 导出密钥 + 清单（解密与校验所需）
els.btnExportKey.addEventListener('click', async () => {
  if (!activeSessionId) return;
  const db = await openDB();
  const session = await getSession(db, activeSessionId);
  if (!session) return;
  const manifest = {
    fileName: session.fileName,
    fileSize: session.fileSize,
    chunkSize: session.chunkSize,
    totalChunks: session.totalChunks,
    fileHash: session.fileHash,
    chunkHashes: session.chunkHashes,
    keyJwk: session.keyJwk,
    algorithm: 'AES-GCM-256, 每分片独立随机 IV，数据布局: iv(12B) || ciphertext || tag(16B)',
  };
  const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${session.fileName}.manifest.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  log('密钥与清单已导出（请妥善保管，泄露即可解密文件）', 'warn');
});

// ---------- Worker 消息 ----------
worker.onmessage = (e) => {
  const msg = e.data;
  switch (msg.type) {
    case 'ready':
      log('Worker 已就绪');
      break;
    case 'state':
      if (msg.session && msg.session.id) activeSessionId = msg.session.id;
      setState(msg.state);
      break;
    case 'progress':
      renderProgress(msg);
      break;
    case 'verifyProgress':
      els.progressBar.style.width = `${(msg.doneBytes / msg.totalBytes) * 100}%`;
      els.progressText.textContent = `校验中 ${(100 * msg.doneBytes / msg.totalBytes).toFixed(1)}% · 分片 ${msg.chunkIndex}/${msg.totalChunks}`;
      break;
    case 'verifyResult':
      setState(msg.ok ? 'done' : 'error');
      if (msg.ok) {
        els.hashResult.textContent = `校验通过 ✔ 文件根哈希(SHA-256)：${msg.fileHash}`;
        log('哈希校验通过：分片顺序与内容均正确');
      } else {
        showError(`校验失败：${msg.message}`);
        log(`校验失败：${msg.message}`, 'error');
      }
      break;
    case 'degraded':
      log(msg.reason, 'warn');
      showError(msg.reason);
      break;
    case 'error':
      showError(msg.message);
      log(msg.message, 'error');
      if (msg.fatal) setState('error');
      else setState('error'); // 可重试错误同样进入 error 态，等待「重试」或「取消」
      break;
    case 'done':
      activeSessionId = msg.session.id;
      setState('done');
      els.progressBar.style.width = '100%';
      els.progressText.textContent = `100% · ${msg.totalChunks}/${msg.totalChunks} 分片`;
      els.hashResult.textContent = `文件根哈希(SHA-256)：${msg.fileHash}`;
      log(`完成！总耗时 ${fmtDuration(msg.activeMs / 1000)}，根哈希 ${msg.fileHash.slice(0, 16)}…`);
      refreshQuota();
      break;
    case 'log':
      log(msg.text, msg.level);
      break;
    default:
      break;
  }
};

function renderProgress(p) {
  const pct = (p.doneBytes / p.totalBytes) * 100;
  els.progressBar.style.width = `${pct}%`;
  els.progressText.textContent = `${pct.toFixed(1)}% · ${fmtBytes(p.doneBytes)} / ${fmtBytes(p.totalBytes)}`;
  els.statSpeed.textContent = `${fmtBytes(p.speedBps)}/s`;
  els.statEta.textContent = fmtDuration(p.etaSec);
  els.statElapsed.textContent = fmtDuration(p.activeMs / 1000);
  els.statChunks.textContent = `${p.chunkIndex} / ${p.totalChunks}`;
}

// ---------- 主线程健康度：PerformanceObserver + FPS ----------
let longtaskCount = 0;
let longtaskWorst = 0;
try {
  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      longtaskCount += 1;
      longtaskWorst = Math.max(longtaskWorst, entry.duration);
      els.statLongtask.textContent = `${longtaskCount} 次 / 最长 ${longtaskWorst.toFixed(0)}ms`;
    }
  });
  observer.observe({ entryTypes: ['longtask'] });
} catch (_) {
  els.statLongtask.textContent = '不支持';
}

let frames = 0;
let fpsWindowStart = performance.now();
(function fpsLoop(now) {
  frames += 1;
  if (now - fpsWindowStart >= 1000) {
    els.statFps.textContent = `${frames} fps`;
    frames = 0;
    fpsWindowStart = now;
  }
  requestAnimationFrame(fpsLoop);
})(performance.now());

function refreshQuota() {
  if (!navigator.storage || !navigator.storage.estimate) {
    els.statQuota.textContent = '不支持';
    return;
  }
  navigator.storage.estimate().then(({ quota = 0, usage = 0 }) => {
    els.statQuota.textContent = `${fmtBytes(usage)} / ${fmtBytes(quota)}`;
  }).catch(() => { els.statQuota.textContent = '未知'; });
}

if (performance.memory) {
  setInterval(() => {
    els.statHeap.textContent = fmtBytes(performance.memory.usedJSHeapSize);
  }, 1000);
} else {
  els.statHeap.textContent = '不支持';
}

refreshQuota();
setInterval(refreshQuota, 5000);
setState('idle');

// 启动时提示历史遗留任务
(async () => {
  try {
    const db = await openDB();
    const all = await listSessions(db);
    const unfinished = all.filter((s) => s.status !== 'done');
    if (unfinished.length) {
      log(`检测到 ${unfinished.length} 个历史未完成任务，重新选择同一文件即可断点续传`);
    }
  } catch (_) { /* 忽略 */ }
})();
