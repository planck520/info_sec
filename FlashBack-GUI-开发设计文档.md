# FlashBack-GUI 开发设计文档

> 版本：v2.0 | 日期：2026-06-11 | 团队规模：4人

---

## 1. 项目概述

将 FlashBack 固件漏洞分析工具封装为带现代科技感 UI 的 Windows 桌面应用，以**离线安装包**形式分发。

- **用户只需安装 IDA Pro**（商业授权限制，不可打包）
- **其余一切内置**：Python 环境、依赖库、前端界面
- **最终交付物**：`FlashBack-Setup.exe` → 桌面快捷方式 + 开始菜单 + 控制面板可卸载

---

## 2. 技术架构

```
┌─────────────────────────────────────────────────────────┐
│                    FlashBack-GUI                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │     pywebview (Edge WebView2) / Electron         │   │
│  │  ┌───────────────────────────────────────────┐  │   │
│  │  │        HTML / CSS / JS (SPA)              │  │   │
│  │  │    暗色科技风 + WebGL 粒子背景              │  │   │
│  │  └──────────────────┬────────────────────────┘  │   │
│  └─────────────────────┼───────────────────────────┘   │
│                        │ HTTP REST + WebSocket          │
│                        │ localhost:18920                │
│  ┌─────────────────────┼───────────────────────────┐   │
│  │              FastAPI 后端                        │   │
│  │  ┌─────────────────┴──────────────────────┐    │   │
│  │  │  scan │ results │ settings │ llm-review │    │   │
│  │  └────────────────────────────────────────┘    │   │
│  │  ┌────────────────────────────────────────┐    │   │
│  │  │  orchestrator → subprocess → IDA       │    │   │
│  │  │  ida_detector / config_manager         │    │   │
│  │  └────────────────────────────────────────┘    │   │
│  └────────────────────────────────────────────────┘   │
│                          │                             │
│  ┌───────────────────────┴────────────────────────┐   │
│  │  资源文件 (安装目录)  backward/ config/ llm/     │   │
│  └────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         │ 用户自行安装
         ▼
    IDA Pro + Hex-Rays
```

### 技术选型

| 层面 | 技术 | 理由 |
|------|------|------|
| 桌面窗口 | **pywebview** + Electron 双模 | pywebview 用系统 Edge WebView2（零额外体积）；Electron 打包 Chromium（180MB）作为备选 |
| 渲染引擎 | Edge WebView2 (Chromium) / Electron Chromium | Win10/11 自带或内置，CSS3 动画/毛玻璃/WebGL 全部支持 |
| 后端 | **FastAPI** + uvicorn | 高性能异步 HTTP，自带 WebSocket 和 Swagger 文档 |
| 前端 | 原生 **HTML/CSS/JS** + Three.js | 最小打包体积，最大设计自由度 |
| 打包 | PyInstaller + NSIS | Python → 文件夹 → 安装包 |

---

## 3. 项目目录结构

```
FlashBack-GUI/
├── main.py                    # 应用入口，pywebview/Electron 双模启动  【成员 D ✅】
│
├── server/                    # FastAPI 后端
│   ├── __init__.py
│   ├── app.py                 # FastAPI 应用创建（CORS + 5路由 + 静态文件）【成员 D ✅】
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── scan.py            # 扫描路由骨架                      【成员 A 🔴】
│   │   ├── results.py         # 结果路由骨架                      【成员 B 🔴】
│   │   ├── settings.py        # 设置路由（GET/POST + detect-ida）  【成员 C 🟡 基本完成】
│   │   └── llm.py             # LLM 审查路由骨架                  【成员 C 🔴】
│   └── websocket.py           # WebSocket 路由骨架                 【成员 A 🔴】
│
├── engine/                    # Python 核心引擎
│   ├── __init__.py
│   ├── orchestrator.py        # FlashBackRunner（scan_directory✅ run_batch🔴 stop✅）【成员 A】
│   ├── ida_detector.py        # IDA 路径自动检测                   【成员 C 🔴】
│   └── config_manager.py      # config.ini 读写                    【成员 C 🔴】
│
├── frontend/                  # Web 前端 (SPA)
│   ├── index.html             # SPA 外壳 + 5 页面 DOM + 模拟脚本    【成员 D ✅】
│   ├── css/
│   │   ├── main.css           # CSS 变量 + 全局样式 + 侧边栏        【成员 D ✅】
│   │   ├── analysis.css       # 分析页样式                          【成员 A 🔴→🟡】
│   │   ├── results.css        # 结果页样式                          【成员 B 🔴→🟡】
│   │   ├── settings.css       # 设置页样式                          【成员 C 🟡】
│   │   └── components.css     # 公共组件（按钮/卡片/输入框/终端等）  【成员 D ✅】
│   ├── js/
│   │   ├── app.js             # SPA 路由 + 全局状态管理             【成员 D ✅】
│   │   ├── api.js             # HTTP + WebSocket 封装               【成员 D ✅】
│   │   ├── analysis.js        # 分析页逻辑（骨架）                  【成员 A 🔴】
│   │   ├── results.js         # 结果页逻辑（骨架）                  【成员 B 🔴】
│   │   ├── settings.js        # 设置页逻辑（LLM 提供商切换）       【成员 C 🟡】
│   │   ├── components.js      # 公共组件（showToast）               【成员 D ✅】
│   │   └── background.js      # WebGL 粒子背景                      【成员 D ✅】
│   ├── fonts/                 # Figtree 字体（3 个 .woff2 文件）
│   │   ├── figtree-latin-wght-normal.woff2
│   │   ├── figtree-latin-ext-wght-normal.woff2
│   │   └── figtree-latin-wght-italic.woff2
│   ├── vendor/
│   │   └── three.module.js    # Three.js r170 本地副本（离线可用）
│   └── assets/
│       └── fonts/
│           └── README.md      # 字体说明（已过时，实际使用 Figtree）
│
├── electron/                  # Electron 集成
│   ├── main.js                # 主进程（spawn Python + frameless 窗口）【成员 D ✅】
│   └── preload.js             # 上下文桥接（窗口控制 IPC）           【成员 D ✅】
│
├── resources/                 # 打包资源（从 FlashBack-main 复制）
│   ├── backward/              # 分析引擎（11 个 .py）— ⚠️ 不可修改
│   ├── config/config.json     # 分析规则（320 行 sink/source 定义）
│   └── llm/                   # LLM 审查脚本（2 个 .py）
│
├── requirements.txt           # Python 依赖                        【成员 D ✅】
├── package.json               # Electron + Three.js npm 依赖        【成员 D ✅】
├── build.py                   # PyInstaller 打包脚本                【成员 D 🔴】
└── installer.nsi              # NSIS 安装包脚本                     【成员 D 🔴】

状态图例：✅ 已完成  🟡 部分完成  🔴 待实现
```

---

## 4. 分析⇄结果数据传递规范

> ⚠️ **这是 A/B 模块间最关键的接口。合并分支时此处必须一致。**

### 4.1 数据流向

```
┌─────────────────────────────────────────────────────────────────┐
│                        分析模块 (A)                              │
│                                                                 │
│  scan.py                                                        │
│  POST /api/scan/start → orchestrator.run_batch()                │
│       │                                                         │
│       ▼                                                         │
│  orchestrator.py 调用 backward/cli.py                            │
│       │                                                         │
│       ▼                                                         │
│  <output_dir>/<device>/<firmware>.json  ←── 原始 JSON 数组      │
│  <output_dir>/<device>/<path_index>.c   ←── 反编译代码文件      │
│                                                                 │
│  WebSocket → 实时推送进度、日志                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
            output_dir 路径（config.ini → config_manager）
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                        结果模块 (B)                              │
│                                                                 │
│  results.py                                                     │
│  扫描 output_dir 下所有 *.json → 聚合 → 增补字段 → 分页返回     │
│                                                                 │
│  GET /api/results        → 列表（含 result_id）                 │
│  GET /api/results/{id}   → 详情（含 decompiled_code）           │
│  GET /api/results/export → 导出（json/csv/md）                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 核心数据结构

#### 分析产出（backward/cli.py 原始格式，不可修改）

```typescript
// <output_dir>/<device>/<firmware>.json → 数组，每个元素：
interface VulnerabilityResult {
  vuln_type:   string;        // CWE 类型，如 "CWE-78"
  sink_func:   string;        // sink 函数名，如 "system"
  source_func: string | null; // source 函数名，如 "getenv"
  param_idx:   number;        // sink 的参数索引（0-based）
  len_idx:     number | null; // 长度参数索引（CWE-120 等有 len 字段时为 number）
  path: Array<{
    func:      string;        // 函数名
    arg_index: number;        // 参数索引
    call_ea:   string;        // 调用地址（hex 字符串，如 "0x401050"）
    func_ea:   string;        // 函数地址（hex，或 "source"/"sink" 标记）
    label:     string | null; // needs_check | certain | sink | source
  }>;
}
```

#### 结果 API 增补字段

```typescript
// results.py 从文件路径提取的增补字段：
interface ResultAugmented extends VulnerabilityResult {
  result_id:    string;  // "{device}/{firmware}/{path_index}"（path_index 1-based）
  device:       string;  // 从文件路径提取：<out>/<device>/<firmware>.json → device
  firmware:     string;  // 从文件路径提取：Path.stem
  path_length:  number;  // item.path.length
}

// GET /api/results/{result_id} 额外包含：
interface ResultDetail extends ResultAugmented {
  decompiled_code: string; // 从 <out>/<device>/<path_index>.c 读取，不存在则 ""
}
```

### 4.3 result_id 格式规范

```
result_id = "{device}/{firmware}/{path_index}"

示例：  "ASUS_GT-AC2900/cfg_server/3"

解析规则（results.py）：
  1. 按 "/" 分割为 3 段：device、firmware、path_index
  2. path_index 为 1-based（前端显示用，内部转 0-based 访问数组）
  3. 定位文件：<output_dir>/<device>/<firmware>.json 的第 (path_index - 1) 条
  4. 读取代码：<output_dir>/<device>/<path_index>.c

⚠️ 注意：path_index 是 1-based！后端 JSON 数组索引是 0-based。
   访问时需 path_index - 1 转换。
```

### 4.4 output_dir 共享机制

```
config.ini
  └── [paths] output_dir = "D:\FlashBack\output"
       │
       ├── orchestrator.py: run_batch() 读取 → subprocess 传给 cli.py
       │
       └── results.py: 读取同一 config.ini → 扫描该目录下的 JSON

统一入口：config_manager.get("paths", "output_dir")
```

### 4.5 WebSocket 消息格式（分析→前端实时推送）

```typescript
// ws://localhost:{port}/ws/logs?task_id=<uuid>

// 服务端 → 客户端 消息类型：
type WSMessage =
  | { type: "log";      level: "INFO"|"WARN"|"ERROR"; message: string;   timestamp: string; }
  | { type: "progress"; completed: number; total: number; current: string; }
  | { type: "done";     success: number; fail: number; }
  | { type: "error";    message: string; }

// 前端回调映射（api.connectWS）：
//   onLog      → type === "log"
//   onProgress → type === "progress"
//   onDone     → type === "done"
//   onError    → type === "error"
```

---

## 5. API 接口规范

> 后端运行在 `http://localhost:{port}`（默认 18920，冲突自动递增到 18921~18929）。前端通过 `window.location.origin` 获取 base URL。

### 5.1 分析任务（成员 A 实现）

```
GET    /api/scan/dir?path=<固件目录>
  → { "firmwares": [
        { "name": "cfg_server", "device": "ASUS_GT-AC2900",
          "path": "D:\\...", "bits": "64", "size": 1234567 }
      ]}

  字段说明（从 orchestrator.scan_directory() 提取）：
  - name:   Path.stem（文件名去后缀）
  - device: Path.parent.name（父目录名，即设备名）
  - path:   文件完整路径
  - bits:   "64" 或 "32"（通过文件名判断）
  - size:   Path.stat().st_size（字节数）

POST   /api/scan/start
  Body: { "firmwares": ["路径1", "路径2"],
          "output_dir": "D:\\output",
          "mode": "standard|nocache|nopropagator",
          "parallel": 2 }
  → { "task_id": "uuid" }

GET    /api/scan/progress/{task_id}
  → { "status": "running|done|error",
      "completed": 5, "total": 10,
      "current": "cfg_server",
      "success": 4, "fail": 1 }

DELETE /api/scan/stop/{task_id}
  → { "ok": true }
```

### 5.2 结果查看（成员 B 实现）

```
GET    /api/results?device=<设备名>&cwe=<CWE-78>&page=1&size=50
  → { "total": 239, "results": [ResultAugmented, ...] }

GET    /api/results/{result_id}
  → ResultDetail（含 decompiled_code）

GET    /api/results/export?device=&cwe=&format=json|csv|markdown
  → 文件下载响应
```

> 增补字段计算方式详见 §4.2。

### 5.3 设置配置（成员 C 实现）

```
GET    /api/settings
  → { "ida_path": "D:\\IDAPro\\...",
      "llm_base_url": "https://api.openai.com/v1",
      "llm_api_key": "sk-****",          ← 脱敏显示
      "max_parallel": 4,
      "theme": "dark" }

POST   /api/settings
  Body: { "ida_path": "D:\\..." }
  → { "ok": true }

POST   /api/settings/detect-ida
  → { "found": true, "path": "D:\\IDAPro\\..." }
  或 { "found": false, "message": "未找到 IDA 安装" }
```

### 5.4 LLM 审查（成员 C 实现）

```
POST   /api/llm-review
  Body: { "result_ids": ["ASUS_GT-AC2900/cfg_server/3"],
          "mode": "direct|reasoning" }
  → { "review_id": "uuid" }

GET    /api/llm-review/{review_id}
  → { "status": "running|done", "results": [...] }
```

---

## 6. 前端 SPA 设计

### 6.1 页面路由

```
#dashboard  → 仪表盘（概览统计 + 快速操作）
#analysis   → 固件分析（扫描执行 + 进度 + 日志）
#results    → 扫描结果（表格 + 详情面板 + 导出）
#settings   → 系统设置（IDA + LLM 配置）
#help       → 帮助页面（快速入门 + 关于）
```

### 6.2 现有 UI 组件库

> ⚠️ **A/B/C 新增 UI 必须复用以下组件，保持风格统一。**

| 组件 | CSS 类 | 文件 | 用途 |
|------|--------|------|------|
| 毛玻璃卡片 | `.panel` + `.panel-body` | main.css | 通用内容容器 |
| 统计卡片 | `.stat-card` | main.css + components.css | 数值统计 + 图标（hover 渐变光晕） |
| 结果卡片 | `.result-card` | components.css | 漏洞列表项（有 severity 色彩变体） |
| 主按钮 | `.btn.btn-primary` | components.css | 青蓝渐变主要操作 |
| 次按钮 | `.btn.btn-secondary` | components.css | 半透明玻璃次要操作 |
| 小按钮 | `.btn.btn-sm` | components.css | 紧凑型按钮 |
| 输入框 | `.input` | components.css | 暗色玻璃输入框 |
| 下拉框 | `.select` | components.css | 暗色玻璃选择器 |
| 终端 | `.terminal` | components.css | 日志输出面板 |
| 进度环 | `.progress-ring-*` | components.css | SVG 环形进度 |
| Toast | `showToast()` | components.js | 底部弹出提示 |
| 页面标题 | `.page-title h1` + `.sub` | main.css | 页面标题 + mono 副标题 |
| 区块标题 | `.section-hd` | main.css | 带状态圆点的区块标题栏 |
| 代码标签 | `.code-label` `.code-value` `.code-path` | main.css | 等宽字体信息展示 |
| 开关 | `.toggle` | components.css | 设置页开关（`<button role="switch">`） |

**工具类**（main.css）：`.flex-row` `.flex-col` `.flex-1` `.flex-between` `.gap-xs` `.gap-sm` `.gap-md` `.gap-lg` `.gap-3` `.text-muted` `.text-sm` `.text-xs` `.font-semibold` `.font-bold`

### 6.3 视觉设计规范

| 元素 | 规范 |
|------|------|
| 背景 | `linear-gradient(to bottom right, #000, #0f172a, #000)` + WebGL 粒子层 |
| 卡片背景 | `rgba(255,255,255,0.10)` + `backdrop-filter: blur(24px)` 毛玻璃 |
| 卡片边框 | `1px solid rgba(255,255,255,0.20)` |
| 卡片圆角 | 24px（面板/卡片）/ 10px（按钮/输入框） |
| 主强调色 | `#3b82f6`（蓝色，CSS: `--accent`） |
| 青色 | `#06b6d4`（CSS: `--accent-cyan`） |
| 紫色 | `#6366f1`（CSS: `--accent-purple`） |
| 危险色 | `#f87171`（红，CSS: `--danger`） |
| 警告色 | `#fbbf24`（琥珀，CSS: `--warning`） |
| 成功色 | `#34d399`（绿，CSS: `--success`） |
| 正文字体 | Figtree Variable (300-900), 14px, weight 500 |
| 代码字体 | Cascadia Code / Consolas / Fira Code, 等宽 |
| 按钮渐变 | `linear-gradient(135deg, #06b6d4, #3b82f6)` |
| 文字三层 | primary: 0.95 / secondary: 0.80 / muted: 0.60（rgba 白透明度） |
| hover 效果 | `translateY(-2px)` + 背景/边框增亮，过渡 0.4s |
| 过渡动画 | 全局 0.3s，卡片 0.4s，cubic-bezier(0.16,1,0.3,1) |
| 可访问性 | `:focus-visible` 焦点环 + `prefers-reduced-motion` 动画禁用 |

> ⚠️ **新增 UI 必须使用 CSS 变量**（`var(--accent)` 而非硬编码 `#3b82f6`），保证未来换肤一致。

---

## 7. 四人分工与 Week 1 计划

> D 的框架工作基本完成。本周 A/B 并行开发核心功能模块，C 先配合文档再开发仪表盘。

### 成员 D：应用框架（✅ 基本完成）

**已交付（与原始设计的主要差异）：**

| 实际交付 | 原始设计 | 说明 |
|---------|---------|------|
| Figtree 字体（3 个 woff2） | Inter + JetBrains Mono | 对齐 frosted-glass 参考设计 |
| 仅 `showToast()` 组件 | 5 个组件（进度条/日志/表格/终端/进度环） | 其余功能通过 HTML 内联实现 |
| WebGL 粒子背景（background.js） | 无 | GPU 波浪粒子，262K 点，Three.js 引擎 |
| Three.js 本地 vendor | 无 | 离线可用，不依赖 CDN |
| Electron 双模支持 | 仅 pywebview | main.py 支持 `--server-only`，Electron 主进程 |
| 5 页面 DOM 骨架 | 3 页面 | 新增仪表盘 + 帮助页 |
| 蓝 accent #3b82f6 | 电光青 #00e5ff | 综合 ChinaCode 参考后调整 |

**待完成（本周）**：
- `build.py` PyInstaller 打包脚本
- `installer.nsi` NSIS 安装包脚本
- 集成测试环境准备

### 成员 A：分析任务模块（本周 5 天）

**负责文件：**

| 文件 | 当前状态 | 工作内容 |
|------|:------:|------|
| `engine/orchestrator.py` | 🟡 scan_directory✅ run_batch🔴 | 实现 `run_batch()`：生成 wrapper → subprocess 调 IDA → 等待完成 |
| `server/routes/scan.py` | 🔴 骨架 | 实现 4 个端点：GET dir / POST start / GET progress / DELETE stop |
| `server/websocket.py` | 🔴 骨架 | 实现 `/ws/logs` 端点：任务连接映射 + 日志/进度广播 |
| `frontend/js/analysis.js` | 🔴 骨架 | 页面逻辑：目录选择→固件列表→启动扫描→WebSocket 实时更新 |
| `frontend/css/analysis.css` | 🟡 已有基础 | 新增样式需保持一致风格 |

**开发顺序建议：**
1. Day 1-2：`orchestrator.run_batch()` — 核心引擎，独立可测
2. Day 2-3：`scan.py` + `websocket.py` — API 层
3. Day 3-5：`analysis.js` — 前端交互，对接 API 和 WebSocket

**UI 约束：**
- 复用现有 `.stat-card` 显示 STATUS/VULNS/ELAPSED
- 复用现有 `.terminal` 显示实时日志
- 复用现有 SVG 进度环 `.progress-ring-*`
- 按钮用 `.btn.btn-primary` / `.btn.btn-secondary`

### 成员 B：结果查看与导出模块（本周 5 天）

**负责文件：**

| 文件 | 当前状态 | 工作内容 |
|------|:------:|------|
| `server/routes/results.py` | 🔴 骨架 | 实现 3 个端点：GET 列表 / GET 详情 / GET 导出 |
| `frontend/js/results.js` | 🔴 骨架 | 页面逻辑：筛选→列表→详情面板→导出 |
| `frontend/css/results.css` | 🟡 已有基础 | 新增样式保持一致 |

**开发顺序建议：**
1. Day 1-2：`results.py` — 扫描 output_dir → 聚合 JSON → 增补字段
2. Day 2-3：`results.py` — 详情读取 .c 文件 + 导出功能
3. Day 3-5：`results.js` — 前端表格 + 筛选 + 详情滑出面板 + 导出

**⚠️ 与 A 的数据对接**（详见 §4）：
- 共享 `output_dir`（通过 `config_manager.get("paths", "output_dir")`）
- 读取 A 的 `<out>/<device>/<firmware>.json` 输出
- `result_id` 格式：`{device}/{firmware}/{path_index}`（1-based）
- 先从 `resources/backward/cli.py` 理解原始 JSON 格式，用模拟数据独立测试

**UI 约束：**
- 结果列表用 `.result-card`（已有 severity 变体 `.critical/.high/.medium/.low`）
- 筛选栏用 `.input` + `.select` + `.btn.btn-secondary`
- 详情面板用 `.panel`

### 成员 C：文档 + 仪表盘（本周前 3-4 天文档，后 3-4 天仪表盘）

#### 第一阶段（Day 1-3/4）：配合 D 完成文档

- 补充 `engine/config_manager.py` 实现
- 补充 `engine/ida_detector.py` 实现
- 补充 `server/routes/settings.py`（当前仅硬编码默认值，需要落地 config.ini）
- 补充 `server/routes/llm.py`（骨架）
- `frontend/js/settings.js`：LLM 提供商切换已有，需补充保存/加载逻辑

#### 第二阶段（Day 3/4-5）：完善仪表盘页面

**当前状态**：仪表盘 HTML DOM 已有（4 个统计卡片 + 最近扫描面板 + 漏洞概览 + 快速操作 + 活动列表），但：
- 无 `registerPage('dashboard', ...)`（app.js 中缺少生命周期）
- 统计数字全是静态 0 或 "--"
- 快速操作按钮三个都是跳转到分析页

**需要做的：**
1. 在 `app.js` 中注册 dashboard 页面生命周期
2. `dashboard.init()`：从 API 拉取统计数据（总扫描数、漏洞数、设备数、运行时间）
3. `dashboard.destroy()`：清理定时器/事件
4. 动态填充统计卡片（`#dash-scans`、`#dash-vulns`、`#dash-devices`、`#dash-uptime`）
5. 动态填充最近扫描 + 漏洞概览面板
6. 快速操作按钮行为修正（New Scan→分析页、View Results→结果页、Settings→设置页）

**仪表盘数据来源**：需从 results API 聚合（B 模块完成后），先用 mock 数据开发。

---

## 8. 开发注意事项

### 8.1 backward/ 目录不可修改

`resources/backward/` 下所有 `.py` 文件是论文分析代码，**严禁修改**。所有新功能通过 `engine/orchestrator.py` 包装层实现。

### 8.2 IDA 加载需要真实文件路径

`backward/cli.py` 通过 IDA `-S` 参数加载，必须是磁盘上的真实文件路径。PyInstaller 临时目录不可用。

### 8.3 前端文件组织

- **SPA 单页**：只有 `index.html`，`<section>` + hash 路由实现多页面
- **JS 隔离**：每个页面模块通过 `init*Page()` / `destroy*Page()` 函数接入
- **CSS 隔离**：全局在 `main.css` + `components.css`，页面在各自 css
- **无框架依赖**：不引入 React/Vue/jQuery，纯原生 JS
- **Three.js**：已本地化到 `frontend/vendor/three.module.js`，离线可用

### 8.4 config.ini 与安装目录分离

- 安装目录：程序文件 + `resources/`
- `%APPDATA%\FlashBack\config.ini`：用户配置（卸载不影响）

### 8.5 并行分析限制

默认并行 4（每个 IDA 实例 500MB+ 内存），用户可在设置中调低。

### 8.6 端口冲突

启动时 socket 探测端口 → 占用则递增。前端 `api.js` 通过 `window.location.origin` 获取 base URL。

### 8.7 IDA 子进程终止

`taskkill /F /T /PID <pid>` 递归终止进程树（`/T` 参数），防止 `win32_remote.exe` 孤儿进程。

### 8.8 result_id 统一格式

`{device}/{firmware}/{path_index}` 三段式。前端从 API 返回字段自行拼接。**path_index 是 1-based**，后端访问数组时需 -1 转换。

### 8.9 新增 UI 必须遵守

1. **复用现有组件** — 有 `.panel` 就别自己写卡片
2. **用 CSS 变量** — 颜色用 `var(--accent)` 不硬编码
3. **风格统一** — `backdrop-filter: blur(24px)`, `border-radius: 24px`, `border: 1px solid rgba(255,255,255,0.20)`
4. **样式放对位置** — 公共样式联系 D 加到 `components.css`，页面样式放各自 css
5. **尊重暗色主题** — 不要引入亮色/白色大面积背景

---

## 9. 附录：文件清单总表（实际状态）

| 文件 | 成员 | 状态 | 说明 |
|------|:----:|:----:|------|
| `main.py` | D | ✅ | ~193 行，pywebview + Electron 双模 |
| `server/__init__.py` | D | ✅ | |
| `server/app.py` | D | ✅ | ~57 行，CORS + 5路由 + StaticFiles |
| `server/routes/__init__.py` | D | ✅ | |
| `server/routes/scan.py` | A | 🔴 | 骨架，~5 行 |
| `server/routes/results.py` | B | 🔴 | 骨架，~5 行 |
| `server/routes/settings.py` | C | 🟡 | ~50 行，硬编码默认值 |
| `server/routes/llm.py` | C | 🔴 | 骨架，~5 行 |
| `server/websocket.py` | A | 🔴 | 骨架，~5 行 |
| `engine/__init__.py` | D | ✅ | |
| `engine/orchestrator.py` | A | 🟡 | ~77 行，scan_directory✅ run_batch🔴 stop✅ |
| `engine/config_manager.py` | C | 🔴 | 待实现 |
| `engine/ida_detector.py` | C | 🔴 | 待实现 |
| `frontend/index.html` | D | ✅ | ~831 行，5 页面 DOM + 模拟脚本 |
| `frontend/css/main.css` | D | ✅ | ~530 行 |
| `frontend/css/components.css` | D | ✅ | ~470 行 |
| `frontend/css/analysis.css` | A | 🟡 | ~25 行，待补充 |
| `frontend/css/results.css` | B | 🟡 | ~15 行，待补充 |
| `frontend/css/settings.css` | C | 🟡 | ~70 行 |
| `frontend/js/app.js` | D | ✅ | ~106 行，5 页面路由 |
| `frontend/js/api.js` | D | ✅ | ~107 行，HTTP + WS |
| `frontend/js/components.js` | D | ✅ | ~29 行，仅 showToast |
| `frontend/js/background.js` | D | ✅ | ~330 行，WebGL 粒子 |
| `frontend/js/analysis.js` | A | 🔴 | 骨架，~10 行 |
| `frontend/js/results.js` | B | 🔴 | 骨架，~13 行 |
| `frontend/js/settings.js` | C | 🟡 | ~43 行，LLM 切换 |
| `frontend/fonts/*.woff2` | D | ✅ | 3 个 Figtree 字重 |
| `frontend/vendor/three.module.js` | D | ✅ | ~1.3MB，离线 Three.js |
| `electron/main.js` | D | ✅ | ~153 行 |
| `electron/preload.js` | D | ✅ | ~11 行 |
| `resources/backward/*` | D | ✅ | 11 个 .py，复制 |
| `resources/config/config.json` | D | ✅ | 320 行，复制 |
| `resources/llm/*` | D | ✅ | 2 个 .py，复制 |
| `requirements.txt` | D | ✅ | 4 个依赖 |
| `package.json` | D | ✅ | Electron + Three.js |
| `build.py` | D | 🔴 | 待实现 |
| `installer.nsi` | D | 🔴 | 待实现 |
| **总计** | | | **约 35 个文件** |

> 状态图例：✅ 已完成  🟡 部分完成  🔴 待实现
