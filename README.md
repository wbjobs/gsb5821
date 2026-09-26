# 本地分片加密工具

选择本地大文件（1GB+），在浏览器内完成分片读取、AES-GCM 加密、SHA-256 哈希，
支持暂停 / 继续 / 取消 / 断点续传，实时展示进度、速度、剩余时间。
纯本地运行：不上传、无任何网络传输。

## 运行

```bash
python3 -m http.server 8000
# 打开 http://localhost:8000
```

## 验证（Node 环境，复用与浏览器完全相同的引擎代码）

```bash
node --expose-gc test/verify.mjs         # 快速套件（256MB）
node --expose-gc test/verify.mjs --1g    # 1GB 验收
```

覆盖：哈希正确性、解密回环、分片顺序、暂停/继续、刷新后续传、取消清理、
加密失败重试、文件删除恢复、配额降级、内存有界。

## 架构

| 文件 | 职责 |
|---|---|
| `js/chunk-core.js` | 纯函数：Streams 读分片 → SHA-256 → AES-GCM → SHA-256 |
| `js/engine.js` | 环境无关调度引擎：状态机、背压并发、重试退避、配额降级、EWMA 速度/ETA |
| `js/worker.js` | Web Worker：执行加解密，Transferable 零拷贝回传 |
| `js/db.js` | IndexedDB：manifest（密钥/元数据）+ chunks（密文/哈希） |
| `js/main.js` | 主线程：UI、rAF 节流刷新、PerformanceObserver 长任务监控、自动降并发 |

## 关键设计

- **内存有界**：8MiB 分片 + 最多 3 个在途分片（背压），内存占用与文件大小无关。
- **断点续传**：manifest 以 `文件名:大小:mtime` 为键持久化；已完成分片落库，
  刷新页面后重新选择同一文件即可续传。
- **哈希链**：最终哈希 = SHA-256(按序拼接的各分片明文哈希)，乱序完成不影响结果。
- **暂停**：在途分片完成并落盘后进入 paused，不丢进度。
- **取消**：AbortController 中止在途读取，清空 IndexedDB 临时数据。
- **重试**：分片失败指数退避重试 3 次；耗尽后进入 error（如文件被删除），可恢复后继续。
- **配额降级**：预估不足或捕获 QuotaExceededError 时切换为仅哈希模式，功能不中断。
- **60fps**：重计算全在 Worker；UI 按 rAF 节流；longtask 过多时自动降低并发。
- **不计时漂移**：速度/ETA 基于 `performance.now()` 单调时钟 + EWMA。
