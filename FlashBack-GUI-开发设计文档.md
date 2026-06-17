# FlashBack-GUI 开发设计文档

> 版本：v1.0 | 日期：2026-06-07 | 团队规模：4人

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
│  │           pywebview → Edge WebView2              │   │
│  │  ┌───────────────────────────────────────────┐  │   │
│  │  │        HTML / CSS / JS (SPA)              │  │   │
│  │  │        暗色科技风前端界面                   │  │   │
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
| 桌面窗口 | **pywebview** | 用系统自带 Edge WebView2 渲染，零额外体积 |
| 渲染引擎 | Edge WebView2 (Chromium) | Win10/11 自带，CSS3 动画/毛玻璃/渐变全部支持 |
| 后端 | **FastAPI** + uvicorn | 高性能异步 HTTP，自带 WebSocket 和 Swagger 文档 |
| 前端 | 原生 **HTML/CSS/JS**（无框架） | 最小打包体积，最大设计自由度 |
| 打包 | PyInstaller + NSIS | Python → 文件夹 → 安装包 |

### 为什么选方案 C（pywebview）而不是 Electron？

| | Electron | pywebview (方案 C) |
|---|---|---|
| 渲染引擎 | 自带 Chromium (~180MB) | 系统自带 Edge WebView2 (0MB) |
| 视觉效果 | ★★★★★ | ★★★★★（同一个渲染引擎） |
| CSS 动画/毛玻璃/渐变 | ✅ | ✅ |
| 打包体积 | ~180MB | ~80MB |
| 语言栈 | JS + Node.js + Python | Python 全栈 + 前端三件套 |

两者底层都是 Chromium 渲染，前端效果完全一致。方案 C 的优势是体积更小、Python 全栈统一、团队不需要学 Electron。

---

## 3. 项目目录结构

```
FlashBack-GUI/
├── main.py                    # 应用入口，启动 FastAPI + pywebview  【成员 D】
│
├── server/                    # FastAPI 后端
│   ├── __init__.py
│   ├── app.py                 # FastAPI 应用创建              【成员 D】
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── scan.py            # 扫描 + 分析任务路由           【成员 A】
│   │   ├── results.py         # 结果查询 + 导出路由           【成员 B】
│   │   ├── settings.py        # 配置 + IDA 检测路由          【成员 C】
│   │   └── llm.py             # LLM 审查路由                 【成员 C】
│   └── websocket.py           # WebSocket 实时日志            【成员 A】
│
├── frontend/                  # Web 前端 (SPA)
│   ├── index.html             # SPA 外壳 + 导航               【成员 D】
│   ├── css/
│   │   ├── main.css           # CSS 变量 + 全局样式           【成员 D】
│   │   ├── analysis.css       # 分析页样式                    【成员 A】
│   │   ├── results.css        # 结果页样式                    【成员 B】
│   │   ├── settings.css       # 设置 + LLM 样式              【成员 C】
│   │   └── components.css     # 公共组件样式(按钮/卡片/输入框)  【成员 D】
│   ├── js/
│   │   ├── app.js             # SPA 路由 + 全局状态管理       【成员 D】
│   │   ├── api.js             # HTTP + WebSocket 封装         【成员 D】
│   │   ├── analysis.js        # 分析页逻辑                    【成员 A】
│   │   ├── results.js         # 结果页逻辑                    【成员 B】
│   │   ├── settings.js        # 设置 + LLM 页逻辑            【成员 C】
│   │   └── components.js      # 公共组件 (进度条/日志/表格)   【成员 D】
│   └── assets/
│       ├── icon.svg           # 应用图标                      【成员 D】
│       └── fonts/             # 🔴1: 离线字体文件 (Inter + JetBrains Mono)
│           └── README.md      #   字体下载说明（不提交二进制到仓库）
│
├── engine/                    # Python 核心引擎
│   ├── __init__.py
│   ├── orchestrator.py        # 分析引擎 (改写 run.py)        【成员 A】
│   ├── ida_detector.py        # IDA 路径自动检测              【成员 C】
│   └── config_manager.py      # config.ini 读写               【成员 C】
│
├── resources/                 # 打包资源 (从 FlashBack-main 复制)
│   ├── backward/              # 分析脚本 (9 个 .py) — ⚠️ 不可修改
│   ├── config/config.json     # 分析规则
│   └── llm/                   # LLM 审查脚本 (2 个 .py)
│
├── requirements.txt           # Python 依赖                    【成员 D】
├── build.py                   # PyInstaller 打包脚本           【成员 D】
└── installer.nsi              # NSIS 安装包脚本                【成员 D】
```

---

## 4. API 接口规范

> 后端运行在 `http://localhost:{port}`（🔴3 默认 18920，冲突时自动递增到 18921~18929），所有接口返回 JSON。前端通过 `window.location.origin` 自动获取 base URL，不硬编码端口号。

### 4.1 分析任务（成员 A 实现）

```
GET    /api/scan/dir?path=<固件目录>
  → { "firmwares": [
        { "name": "cfg_server", "device": "ASUS_GT-AC2900",
          "path": "D:\\...", "bits": "64", "size": 1234567 }
      ]}

  字段说明（均从 run.py 的 _walk_files() 逻辑提取）：
  - name:   Path.stem（文件名去后缀）
  - device: Path.parent.name（父目录名，即设备名）
  - path:   文件完整路径
  - bits:   "64" 或 "32"（后端通过 "_32" not in filename 判断，无法精确到 ARM/MIPS 架构）
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

### 4.2 结果查看（成员 B 实现）

> **数据来源：** backward/cli.py 输出 `<out>/<device>/<firmware>.json`，文件内容为 JSON 数组。
> 每条元素的字段由 `Analyzer.process_single_sink()` 定义（见 `backward/cli.py` 第 88-112 行）。
> API 层在返回前需**从文件路径提取 `device`/`firmware`** 并**计算 `result_id`/`path_length`**。

#### 后端原始 JSON 格式（不可修改）

```jsonc
// <out>/<device>/<firmware>.json → 数组，每个元素：
{
  "vuln_type":   "CWE-78",       // string        — CWE 类型
  "sink_func":   "system",       // string        — sink 函数名
  "source_func": "getenv",       // string | null — source 函数名（实际经过过滤总为 string）
  "param_idx":   0,              // int           — sink 的参数索引
  "len_idx":     null,           // int | null    — 长度参数索引（CWE-120 等有 len 字段时非空）
  "path": [
    {
      "func":      "main",       // string        — 函数名
      "arg_index":  0,           // int           — 参数索引
      "call_ea":   "0x401050",   // string        — 调用地址（hex 字符串）
      "func_ea":   "0x401000",   // string        — 函数地址（hex，或 "source"/"sink" 标记）
      "label":     "certain"     // string | null — needs-check / certain / sink / source
    }
  ]
}
```

#### API 层响应（在原始字段基础上增补）

```
GET    /api/results?device=<设备名>&cwe=<CWE-78>&page=1&size=50
  → {
      "total": 239,
      "results": [
        {
          // ─── 后端原始字段（透传）─────────────────
          "vuln_type":   "CWE-78",
          "sink_func":   "system",
          "source_func": "getenv",
          "param_idx":   0,
          "len_idx":     null,
          // ─── API 层增补字段（从文件路径计算）────
          "result_id":   "ASUS_GT-AC2900/cfg_server/3",
          "device":      "ASUS_GT-AC2900",
          "firmware":    "cfg_server",
          "path_length": 3
        }
      ]
    }

  增补字段计算方式：
  - result_id:   f"{device}/{firmware}/{path_index}"  (path_index 为 1-based)
  - device:      从 JSON 文件路径提取：<out>/<device>/<firmware>.json → device
  - firmware:    从 JSON 文件路径提取：<firmware> = Path.stem
  - path_length: len(item["path"])

GET    /api/results/{result_id}
  → 返回单条完整结果（原始字段 + 增补字段 + 反编译代码）。
  
  result_id 解析：三段式 "{device}/{firmware}/{path_index}"
    - 在 <out>/<device>/<firmware>.json 中定位第 path_index 条（1-based）path
    - 在 <out>/<device>/<path_index>.c 中读取对应的反编译代码
  
  响应格式：
  {
    "result_id":   "ASUS_GT-AC2900/cfg_server/3",
    "vuln_type":   "CWE-78",
    "sink_func":   "system",
    "source_func": "getenv",
    "param_idx":   0,
    "len_idx":     null,
    "device":      "ASUS_GT-AC2900",
    "firmware":    "cfg_server",
    "path":        [ { "func":"...", "arg_index":0, ... }, ... ],
    "decompiled_code": "/* Function: main @ 0x401000 */\n..."
  }
  注：decompiled_code 从 <out>/<device>/<path_index>.c 文件读取（由 cli.py 的
  _write_paths_c_files() 输出），如文件不存在则返回空字符串。

GET    /api/results/export?device=&cwe=&format=json|csv|markdown
  → 文件下载响应
  - json:  原样输出（后端 JSON + 增补字段）
  - csv:   扁平化，列: vuln_type, sink_func, source_func, device, firmware, path_length
  - markdown: 同上，表格格式
```

### 4.3 设置配置（成员 C 实现）

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

### 4.4 LLM 审查（成员 C 实现）

```
POST   /api/llm-review
  Body: { "result_ids": ["ASUS_GT-AC2900/cfg_server/3", "D-LINK_COVR/httpd/1"],
          "mode": "direct|reasoning" }
  → { "review_id": "uuid" }
  注：result_ids 使用 🔴5 定义的三段式格式 {device}/{firmware}/{path_index}

GET    /api/llm-review/{review_id}
  → { "status": "running|done", "results": [...] }
```

### 4.5 WebSocket 实时日志（成员 A 实现）

```
ws://localhost:18920/ws/logs?task_id=<task_id>

服务端推送格式:
{ "type": "log",      "level": "INFO",  "message": "开始分析 ASUS GT-AC2900...",
  "timestamp": "12:30:01" }
{ "type": "progress", "completed": 3,   "total": 10,
  "current": "cfg_server" }
{ "type": "done",     "success": 8,     "fail": 2 }
{ "type": "error",    "message": "IDA 启动失败: ida64.exe 未找到" }
```

---

## 5. 前端 SPA 设计

### 5.1 页面路由

```
#analysis  → 分析页（固件扫描 + 分析执行 + 进度 + 日志）
#results   → 结果页（结果表格 + 详情面板 + 导出）
#settings  → 设置页（IDA 配置 + LLM 配置 + 关于）
```

### 5.2 页面布局

**分析页：**
```
┌──────────────────────────────────────────────────┐
│  ⚡ FlashBack  │  固件分析  │  结果查看  │  设置   │  ← 顶部导航
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌─ 固件目录 ───────────────────────────────┐   │
│  │  [_____________________________] [浏览]   │   │
│  │  [_____________________________] [输出]   │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌─ 固件列表 ──────┐  ┌─ 分析配置 ──────────┐   │
│  │ 📁 ASUS_GT-AC2900│  │ 模式: ○标准 ○无缓存  │   │
│  │  ☑ cfg_server   │  │ 并行: [2]            │   │
│  │  ☑ httpd        │  │                      │   │
│  │ 📁 D-LINK_COVR   │  │ [▶ 开始分析]         │   │
│  │  ☐ cfg_server   │  └──────────────────────┘   │
│  └─────────────────┘                              │
│                                                  │
│  ┌─ 分析进度 ───────────────────────────────┐   │
│  │  ████████████░░░░░░░░  60%  (6/10)        │   │
│  │  当前: cfg_server  ✓ 已完成               │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌─ 实时日志 ───────────────────────────────┐   │
│  │  [12:30:01 INFO] 开始分析 ASUS...         │   │
│  │  [12:30:15 WARN] 发现 3 条 CWE-78 路径    │   │
│  │  [12:30:22 INFO] 分析完成: cfg_server     │   │
│  └──────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
```

**结果页：**
```
┌──────────────────────────────────────────────────┐
│  ⚡ FlashBack  │  固件分析  │  结果查看  │  设置   │
├──────────────────────────────────────────────────┤
│  设备: [全部 ▼]  CWE: [全部 ▼]  🔍 [搜索...]    │  导出: [JSON ▼] │
├──────────────────────────────────────────────────┤
│  ┌─ 结果列表 ──────────────────────────────────────┐   │
│  │  vuln_type │ sink_func ← source_func │ device    │   │
│  │  CWE-78    │ system  ← getenv  │ ASUS_GT-..│   │
│  │  CWE-120   │ strcpy  ← recv    │ D-LINK_.. │   │
│  │  CWE-94    │ eval    ← get_cgi │ TP-LINK_..│   │
│  │  ...                                          │   │
│  └────────────────────────────────────────────────┘   │
│                                                  │
│  ┌─ 详情面板 ───────────────────────────────┐   │
│  │  漏洞: CWE-78 OS命令注入                   │   │
│  │  路径: getenv → sprintf → system          │   │
│  │                                            │   │
│  │  ┌─ 反编译代码 ───────────────────────┐   │   │
│  │  │ /* Function: main @ 0x401000 */     │   │   │
│  │  │ v1 = getenv("QUERY_STRING");        │   │   │
│  │  │ sprintf(cmd, "ping %s", v1);        │   │   │
│  │  │ system(cmd);                        │   │   │
│  │  └────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
```

**设置页：**
```
┌──────────────────────────────────────────────────┐
│  ⚡ FlashBack  │  固件分析  │  结果查看  │  设置   │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌─ IDA Pro 配置 ──────────────────────────┐    │
│  │  IDA 安装路径:                            │    │
│  │  [D:\Program Files\ida9.1\windows    ]   │    │
│  │  [🔍 自动检测]  [📁 手动选择]  [💾 保存]   │    │
│  │  ✓ 已检测到 ida64.exe                     │    │
│  └──────────────────────────────────────────┘    │
│                                                  │
│  ┌─ LLM API 配置 ──────────────────────────┐    │
│  │  Base URL:                                │    │
│  │  [https://api.openai.com/v1           ]   │    │
│  │  API Key:                                 │    │
│  │  [••••••••••••••••••••            ] [👁]  │    │
│  │  [💾 保存]                                │    │
│  └──────────────────────────────────────────┘    │
│                                                  │
│  ┌─ 关于 ──────────────────────────────────┐    │
│  │  FlashBack GUI v1.0                       │    │
│  │  基于 FlashBack 论文 (CCS 2026)           │    │
│  │  团队: XXX                                │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

### 5.3 视觉设计规范

| 元素 | 规范 |
|------|------|
| 背景色 | `#0a0e17`（深蓝黑） |
| 卡片背景 | `rgba(255,255,255,0.03)` + `backdrop-filter: blur(20px)` 毛玻璃 |
| 主强调色 | `#00e5ff`（电光青） |
| 副强调色 | `#7c3aed`（科技紫） |
| 危险/警告色 | `#ff4757`（红）、`#ffa502`（橙） |
| 成功色 | `#2ed573`（绿） |
| 正文字体 | Inter, 14px, `#e0e0e0` |
| 代码字体 | JetBrains Mono, 13px |
| 卡片圆角 | 12px |
| 边框 | `1px solid rgba(0,229,255,0.15)` |
| 按钮渐变 | `linear-gradient(135deg, #00e5ff, #7c3aed)` |
| 发光阴影 | `box-shadow: 0 0 20px rgba(0,229,255,0.15)` |

#### 🔴1 字体离线化策略

字体文件不提交到 Git 仓库（二进制体积大），但**打包时必须打入安装包**。策略：

1. **开发阶段**：CSS 使用 `@font-face` 本地路径优先（指向 `frontend/assets/fonts/`），`url()` 中 CDN 作为 fallback
2. **字体下载**：成员自行从 Google Fonts 下载 Inter（Regular/Medium/SemiBold）和 JetBrains Mono（Regular）的 `.woff2` 文件到 `frontend/assets/fonts/`
3. **运行时检测**：`index.html` 中 JS 检测字体是否真实可用（对比 Inter 和系统 fallback 的文字宽度），不可用时页面顶部显示黄色警告条提示用户
4. **系统降级链**：`Inter, 'Segoe UI', system-ui, -apple-system, sans-serif` 和 `'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace`

---

## 6. 四人垂直切分

> 核心原则：**每个人负责一个完整的功能模块，从后端到前端全栈，可以独立开发、独立验证。**

```
┌─────────────────────────────────────────────────────┐
│                    成员 D：应用框架                   │
│   main.py + app.py + SPA外壳 + 全局样式 + 公共组件    │
│   PyInstaller + NSIS 打包部署                        │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  成员 A   │  │  成员 B   │  │     成员 C        │  │
│  │ 分析任务  │  │ 结果查看  │  │ 设置与 LLM 审查   │  │
│  │          │  │          │  │                  │  │
│  │ 后端:    │  │ 后端:    │  │ 后端:             │  │
│  │ scan.py  │  │ results  │  │ settings.py      │  │
│  │ ws.py    │  │ .py      │  │ llm.py           │  │
│  │ engine/  │  │          │  │ 引擎:             │  │
│  │ orches-  │  │ 前端:    │  │ ida_detector.py  │  │
│  │ trator   │  │ results  │  │ config_manager   │  │
│  │          │  │ .css/js  │  │                  │  │
│  │ 前端:    │  │          │  │ 前端:             │  │
│  │ analysis │  │          │  │ settings.css/js  │  │
│  │ .css/js  │  │          │  │                  │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

### 成员 D：应用框架与打包部署

> **⚠️ 成员 D 需要最先完成基础骨架（预计 2-3 天），其他三人依赖这些公共设施。**

#### 负责文件

| 文件 | 职责 |
|------|------|
| `main.py` | 应用入口流程：<br>1. 🔴3 探测可用端口（默认 18920，被占用则自动尝试 18921~18929）<br>2. 检查 resource_dir（`backward/` 等必须存在）<br>3. 🔴2 后台线程启动 uvicorn，`threading.Event` 等待 ready（超时 5 秒报错）<br>4. uvicorn ready 后创建 pywebview 窗口加载 `index.html`<br>5. 关闭窗口时优雅停止 uvicorn |
| `server/app.py` | FastAPI 应用：配置 CORS（允许 pywebview 的 localhost 请求）、注册各路由模块、lifespan 生命周期事件 |
| `frontend/index.html` | SPA 外壳：`<head>` 引入所有 CSS 文件，`<body>` 包含导航栏 `<nav>` + 三个 `<section id="page-*">` 占位容器 + 引入所有 JS 文件 |
| `frontend/css/main.css` | CSS 变量体系（颜色/字体/间距/圆角）+ 导航栏样式 + 全局 reset + 字体引入 |
| `frontend/css/components.css` | 公共组件样式：`.btn`（渐变按钮）、`.btn-primary`、`.card`（毛玻璃卡片）、`.input`（暗色输入框）、`.badge`（CWE 类型标签）、`.scrollbar`（自定义滚动条） |
| `frontend/js/app.js` | SPA 路由控制器：监听 `hashchange` 事件切换三个页面的显示/隐藏。全局状态对象 `AppState`。提供 `navigateTo(page)` 和 `getPageContainer(page)` 方法 |
| `frontend/js/api.js` | HTTP + WebSocket 封装。暴露 `api.get(path, params)`, `api.post(path, body)`, `api.del(path)`, `api.connectWS(path, callbacks)`。<br>🔴3 **BASE_URL 自动检测**：从 `window.location.origin` 获取，不硬编码端口号，适配动态端口场景。<br>🔴 隐式修复 **WebSocket 断线重连**：意外断开时指数退避重连（最多 3 次，间隔 1s/2s/4s）。 |
| `frontend/js/components.js` | 可复用 JS 组件函数：`createProgressBar(container, options)`, `createLogViewer(container)`, `createResultTable(container, columns)`, `showToast(message, type)` |
| `frontend/assets/icon.svg` | 应用图标 |
| `requirements.txt` | Python 依赖列表 |
| `build.py` | PyInstaller 打包脚本 |
| `installer.nsi` | NSIS 安装包脚本 |

#### 关键接口（供其他成员使用）

```javascript
// ===== api.js — HTTP 请求封装 =====
// 所有方法自动拼接 base URL (http://localhost:18920)

await api.get('/api/scan/dir', { path: 'D:\\firmware' });
await api.post('/api/scan/start', { firmwares: [...], mode: 'standard' });
await api.get('/api/results', { device: 'ASUS', cwe: 'CWE-78' });
await api.post('/api/settings', { ida_path: 'D:\\...' });

// ===== api.js — WebSocket 连接 =====
const ws = api.connectWS('/ws/logs?task_id=xxx', {
    onLog:      (msg) => { /* msg = {level, message, timestamp} */ },
    onProgress: (p)   => { /* p = {completed, total, current} */ },
    onDone:     (s)   => { /* s = {success, fail} */ },
    onError:    (e)   => { /* e = {message} */ }
});
ws.close();  // 断开连接

// ===== app.js — 页面注册与导航 =====
// 每个页面模块注册自己的初始化/销毁函数
AppState.registerPage('analysis', {
    init: initAnalysisPage,     // 进入页面时调用
    destroy: destroyAnalysisPage // 离开页面时调用
});
navigateTo('analysis');  // 跳转到分析页

// ===== components.js — 公共 UI 组件 =====
createProgressBar(container, { total: 10 });
// → 返回 { update(completed, currentLabel), complete(), error(msg) }

createLogViewer(container);
// → 返回 { addLog(level, message), clear() }

createResultTable(container, ['vuln_type', 'sink_func', 'source_func', 'device']);
// → 返回 { setData(rows), onRowClick(callback), clear() }
//    rows 的每个元素直接对应 /api/results 返回的 results 数组项
//    表格自动以列的 key 从 row 对象取值：row['vuln_type'], row['sink_func'], ...
```

#### 验证方式

1. 启动 `main.py`，看到 pywebview 窗口弹出，显示空白 SPA 页面
2. 点击导航栏三个 Tab，页面内容区正确切换
3. 浏览器打开 `http://localhost:18920/docs` 看到 Swagger 文档页面
4. `http://localhost:18920/api/settings` 返回默认配置 JSON

---

### 成员 A：分析任务模块

> **工作边界：** 从"用户选择固件目录"到"分析完成，产出 JSON 结果文件"的完整链路。

#### 负责文件

| 文件 | 职责 |
|------|------|
| `engine/orchestrator.py` | 将现有 `run.py` 重构为 `FlashBackRunner` 类 |
| `server/routes/scan.py` | `/api/scan/*` 路由处理器 |
| `server/websocket.py` | `/ws/logs` WebSocket 端点 |
| `frontend/css/analysis.css` | 分析页专有样式 |
| `frontend/js/analysis.js` | 分析页前端逻辑 |

#### 后端设计要点

**`engine/orchestrator.py` — FlashBackRunner 类：**

```python
class FlashBackRunner:
    def __init__(self, ida_path: Path, resource_dir: Path, config_path: Path):
        """resource_dir: backward/ 所在目录，config_path: config.json 路径"""

    def scan_directory(self, path: Path) -> List[FirmwareInfo]:
        """递归扫描目录，跳过 .i64/.idb/.id0/.id1/.id2/.nam/.til/.cfg"""

    def run_batch(self, firmwares: List[Path], output_dir: Path,
                  mode: str = "standard", parallel: int = 1,
                  on_progress: Callable = None,
                  on_log: Callable = None) -> Dict[str, bool]:
        """批量分析，返回 {文件名: 成功/失败}。

        mode: "standard" → backward/cli.py
              "nocache"   → backward/cli_discache.py
              "nopropagator" → backward/cli_dispropagtor.py

        内部流程: 生成临时 wrapper 脚本 → subprocess 启动 IDA → 等待完成
        
        🔴4 进程终止：通过 subprocess.Popen 启动 IDA 时保存 pid。
        终止分析时调用 `taskkill /F /T /PID <pid>` 递归杀进程树，
        防止 IDA 子进程（如 win32_remote.exe）变成孤儿进程残留。"""

    def stop(self) -> None:
        """🔴4 终止当前运行的 IDA 进程及其所有子进程。"""
        # Windows: taskkill /F /T /PID <pid>
        # 不使用 Popen.kill() —— 它只杀父进程，子进程会残留

    def _create_wrapper_script(self, script_path, config, output) -> Path:
        """生成 IDA 临时 wrapper 脚本（复用 run.py 现有逻辑）"""

    def _build_ida_cmd(self, is_64bit, wrapper, log_path, target) -> List[str]:
        """构建 IDA 命令行: ida64.exe -A -Swrapper -Llog target"""
```

**`server/routes/scan.py` — 分析路由：**

- `GET /api/scan/dir` — 调用 `runner.scan_directory()`，返回固件列表
- `POST /api/scan/start` — 接收参数 → 创建 `task_id` → 用 `asyncio.to_thread()` 在后台运行 `runner.run_batch()` → 立即返回 `task_id`
- `GET /api/scan/progress/{task_id}` — 从内存 dict 返回任务状态
- `DELETE /api/scan/stop/{task_id}` — 🔴4 终止分析任务。Windows 上必须使用 `taskkill /F /T /PID <ida-pid>` 递归终止整棵进程树（避免 IDA 子进程变成孤儿），然后清理临时 wrapper 脚本

任务状态管理：用内存字典 `tasks: Dict[str, TaskState]` 存储运行中任务的状态，通过 `on_progress` 和 `on_log` 回调实时更新。

**`server/websocket.py` — 日志推送：**

- 维护 `{task_id: [WebSocket]}` 连接映射
- 在 `on_progress` 和 `on_log` 回调中广播消息给对应 task_id 的所有连接
- 任务完成后自动关闭所有相关 WebSocket 连接

#### 前端设计要点

**`frontend/js/analysis.js`：**

1. 页面初始化：渲染固件目录输入框 + 浏览按钮 + 输出目录输入框
2. 用户选择固件目录 → 调用 `api.get('/api/scan/dir')` → 渲染固件树（checkbox 列表，按 device 分组）
3. 用户勾选固件 + 选择分析模式 + 点击"开始分析"
4. 调用 `api.post('/api/scan/start')` → 获取 `task_id`
5. 建立 WebSocket：`api.connectWS('/ws/logs?task_id=xxx', callbacks)`
   - `onLog`: 追加日志行（颜色标记 INFO/WARN/ERROR）
   - `onProgress`: 更新进度条和当前分析文件名
   - `onDone`: 显示完成弹窗
   - `onError`: 显示错误信息
6. 对外暴露 `initAnalysisPage()` 和 `destroyAnalysisPage()` 供 `app.js` 调用

#### 验证方式

1. 选一个固件目录 → 点击"开始分析"
2. 看到进度条更新 + 日志窗口实时滚动
3. 输出目录下出现 `<device>/<binary>.json` 结果文件
4. **全程不需要其他成员的模块参与**

---

### 成员 B：结果查看与导出模块

> **工作边界：** 从"读取分析产出的 JSON 文件"到"用户浏览结果详情、导出报告"的完整链路。

#### 负责文件

| 文件 | 职责 |
|------|------|
| `server/routes/results.py` | `/api/results/*` 路由处理器 |
| `frontend/css/results.css` | 结果页专有样式 |
| `frontend/js/results.js` | 结果页前端逻辑 |

#### 后端设计要点

**`server/routes/results.py`：**

- `GET /api/results` — 扫描输出目录下所有 `*.json` 文件，汇总结果。支持：
  - `?device=ASUS_GT-AC2900` — 按设备筛选
  - `?cwe=CWE-78` — 按 CWE 类型筛选
  - `?page=1&size=50` — 分页
  - 返回 `{total, results: [{result_id, vuln_type, sink_func, source_func, param_idx, len_idx, device, firmware, path_length}]}`
  - 字段名与后端 JSON 一致，增补字段见 §4.2 API 规范

- `GET /api/results/{result_id}` — 读取单条完整结果。result_id 为 `{device}/{firmware}/{path_index}` 三段式（🔴5）。附带读取对应 `<device>/<path_index>.c` 反编译代码文件

- `GET /api/results/export?format=json|csv|md` — 按当前筛选条件导出：
  - `json`: 原样输出
  - `csv`: 扁平化输出（vuln_type, sink_func, source_func, device, firmware, path_length）
  - `md`: Markdown 表格格式，适合直接粘贴到报告

#### 前端设计要点

**`frontend/js/results.js`：**

1. 页面初始化：加载结果列表（第一页），渲染表格
2. 筛选栏：设备下拉（从结果中动态提取）、CWE 类型下拉、搜索输入框
3. 表格：每行显示 CWE 类型（彩色 badge）、sink、source、设备名、路径长度
4. 点击行 → 右侧滑出详情面板：
   - 显示完整路径步骤（sink → ... → source，带箭头连接）
   - 每个步骤展示函数名 + 参数 + 调用地址
   - 如有反编译代码，在代码块中展示
5. 导出按钮：下拉选择格式 → 触发文件下载
6. 对外暴露 `initResultsPage()` 和 `destroyResultsPage()`

#### 验证方式

1. 在输出目录下手动放几个模拟的 JSON 结果文件（格式参考 `backward/cli.py` 的 `_write_paths_c_files`）
2. 打开结果页 → 看到表格正确渲染
3. 点击某行 → 详情面板展开
4. 点击导出 → 成功下载文件
5. **不需要成员 A 的完整分析流程也能独立测试**

---

### 成员 C：设置与 LLM 审查模块

> **工作边界：** (1) IDA 路径配置 + 自动检测；(2) LLM API 配置 + 审查任务执行；(3) 以上全部的前后端交互。

#### 负责文件

| 文件 | 职责 |
|------|------|
| `engine/config_manager.py` | config.ini 读写管理 |
| `engine/ida_detector.py` | IDA Pro 安装路径自动检测 |
| `server/routes/settings.py` | `/api/settings/*` 路由处理器 |
| `server/routes/llm.py` | `/api/llm-review/*` 路由处理器 |
| `frontend/css/settings.css` | 设置页 + LLM 面板专有样式 |
| `frontend/js/settings.js` | 设置页 + LLM 面板前端逻辑 |

#### 后端设计要点

**`engine/config_manager.py` — ConfigManager 类：**

```python
class ConfigManager:
    """管理 %APPDATA%\FlashBack\config.ini"""
    
    # config.ini 结构:
    # [ida]
    # path = D:\Program Files\ida9.1\windows
    # 
    # [llm]
    # base_url = https://api.openai.com/v1
    # api_key = sk-xxxx
    # 
    # [app]
    # first_run = true
    # max_parallel = 4
    # theme = dark
    
    def load(self) -> dict
    def save(self) -> None
    def get(self, section: str, key: str) -> str
    def set(self, section: str, key: str, value: str) -> None
    def is_first_run(self) -> bool
    def mark_initialized(self) -> None
```

**`engine/ida_detector.py`：**

```python
def detect_ida() -> Path | None:
    """自动检测 IDA 安装路径。
    扫描顺序:
    1. config.ini 中已保存的路径
    2. C:\Program Files\IDA Pro *\*
    3. D:\Program Files\ida*\*
    4. 注册表 HKLM\SOFTWARE\...
    5. 返回 None（表示未找到）
    """

def verify_ida_path(path: Path) -> bool:
    """检查目录下是否有 ida64.exe 或 ida.exe"""

def prompt_ida_path() -> Path:
    """打开文件夹选择对话框，让用户手动选择"""
```

**`server/routes/settings.py`：**

- `GET /api/settings` — 返回当前所有配置（`api_key` 脱敏显示为 `sk-****xxxx`）
- `POST /api/settings` — 接收更新并保存到 config.ini
- `POST /api/settings/detect-ida` — 调用 `detect_ida()`；找到则自动保存路径并返回；未找到返回 `{found: false}`

**`server/routes/llm.py`：**

- `POST /api/llm-review` — 接收 `{result_ids, mode}`：
  1. 从 config_manager 读取 LLM API 配置
  2. 选择脚本：`mode=="direct"` → `LLM_Direct_Prompt.py`，`"reasoning"` → `LLM_Reasoning_Guided.py`
  3. 通过 subprocess 调用脚本，注入 `input_root`/`output_root`/`base_url`/`api_key` 参数
  4. 返回 `review_id`
- `GET /api/llm-review/{review_id}` — 查询审查进度和结果

#### 前端设计要点

**`frontend/js/settings.js`：**

1. **IDA 配置区：**
   - 显示当前路径（只读文本框）
   - "自动检测"按钮 → 调用 `POST /api/settings/detect-ida`
   - "手动选择"按钮 → 调用系统文件对话框（通过 pywebview 的 JS API 或后端辅助）
   - 检测结果提示（✓ 已检测到 / ✗ 未找到）
   - "保存"按钮 → 调用 `POST /api/settings`

2. **LLM 配置区：**
   - Base URL 输入框
   - API Key 输入框（密码类型，带显示/隐藏切换按钮）
   - "保存"按钮

3. **LLM 审查面板**（可嵌入结果页或在设置页独立）：
   - 选择审查模式（direct / reasoning）
   - 启动审查按钮
   - 审查进度显示
   - 审查结果展示

4. 对外暴露 `initSettingsPage()` 和 `destroySettingsPage()`

#### 验证方式

1. **设置功能：** 改 IDA 路径 → 保存 → 刷新页面 → 路径还在。点"自动检测" → 没找到会提示 → 手动选择 → 保存成功
2. **LLM 审查：** 配置 API → 选几个已有结果 → 启动审查 → 看到进度 → 拿到审查结果
3. **不需要成员 A/B 的分析流程也能独立测试设置功能**

---

## 7. 开发顺序与时间线

```
第 1 周（D 先行 2-3 天，其他人熟悉代码）

  成员 D: 搭建公共基础骨架
    → main.py + app.py + index.html + main.css + components.css
    → app.js (SPA路由) + api.js + components.js
    → 完成后其他人可以往骨架里填充模块
    
  成员 A: 阅读 run.py + backward/ 源码，理解 wrapper 机制
  成员 B: 阅读 backward/cli.py，理解 JSON 输出格式
  成员 C: 阅读 LLM 脚本源码，理解 config.ini 设计


第 1-2 周（四人并行开发各自模块）

  成员 A ──→ orchestrator.py → scan.py + ws.py → analysis.css + analysis.js
  成员 B ──→ results.py → results.css + results.js
  成员 C ──→ config_manager.py + ida_detector.py → settings.py + llm.py → settings.css + settings.js
  成员 D ──→ build.py + installer.nsi + 集成测试环境准备


第 2-3 周（集成 + 联调）

  成员 D: 将 A/B/C 的模块集成到完整应用 → 解决集成问题
  全员: 端到端测试 + Bug 修复
  成员 D: 最终 NSIS 打包 → 在干净 Windows 虚拟机上验证安装流程


第 3 周（收尾）

  全员: 竞赛材料准备（演示视频、PPT 截图、使用文档）
```

---

## 8. 开发环境配置

```bash
# 统一 Python 版本
Python 3.12.x

# 所有人安装（共 4 个依赖）
pip install fastapi==0.115.6 uvicorn==0.34.0 pywebview==5.3.2 requests==2.32.3

# 仅成员 D 额外安装
pip install pyinstaller==6.11.0

# 项目仓库结构（所有人保持一致）
FlashBack-GUI/
├── main.py
├── server/
├── frontend/
├── engine/
├── resources/    # 从 FlashBack-main 复制
└── requirements.txt
```

---

## 9. 注意事项

### 9.1 backward/ 目录不可修改

`resources/backward/` 下的所有 `.py` 文件是论文对应的后端分析代码，**严禁修改**。所有新功能通过 `engine/orchestrator.py` 的包装层实现。

### 9.2 IDA 加载需要真实文件路径

`backward/cli.py` 通过 IDA 的 `-S` 参数加载，必须是磁盘上的真实文件路径。安装时必须将 `resources/` 释放在安装目录下，PyInstaller 的临时目录不可用（IDA 不认识）。

### 9.3 前端文件组织

- **SPA 单页**：只有一个 `index.html`，通过 `<section>` + hash 路由实现多页面
- **JS 隔离**：每个页面模块通过 `init*Page()` / `destroy*Page()` 函数接入，互不冲突
- **CSS 隔离**：全局样式在 `main.css` + `components.css`，页面样式在各自的 css 文件
- **无框架依赖**：不引入 React/Vue/jQuery，纯原生 JS

### 9.4 config.ini 与安装目录分离

- 安装目录：存放程序文件 + `resources/`（可能被用户误删）
- `%APPDATA%\FlashBack\config.ini`：存放用户配置（卸载不影响）

### 9.5 并行分析限制

默认限制并行数为 4（硬编码在 `config_manager.py` 默认值中），因为每个 IDA 实例消耗 500MB+ 内存。用户可在设置中调低。

### 9.6 🔴1 字体离线化

应用以离线安装包分发，字体不能依赖 Google Fonts CDN：

- 字体文件（`.woff2`）放入 `frontend/assets/fonts/`，不提交 Git（二进制大），但打包时打入安装包
- CSS 使用 `@font-face` 本地路径优先 + CDN fallback
- `index.html` 启动时 JS 检测字体是否真实可用，不可用时顶部显示黄色警告
- 字体降级链：`Inter → Segoe UI → system-ui → sans-serif`，`JetBrains Mono → Cascadia Code → Consolas → monospace`

### 9.7 🔴2 启动竞态

uvicorn 启动需要 1~2 秒加载模块，pywebview 不等待可能加载到未 ready 的服务导致白屏：

- `main.py` 使用 `threading.Event` 同步：后台线程启动 uvicorn → ready 后 `event.set()`
- 主线程 `event.wait(timeout=5.0)` 后才创建 pywebview 窗口
- 超时未 ready 则报错退出（返回码 1）

### 9.8 🔴3 端口冲突

端口 18920 可能被其他程序占用（或用户开了两个 FlashBack 实例）：

- 启动时用 socket 探测端口是否可用（TCP connect 到 127.0.0.1）
- 占用则自动尝试 18921、18922...最多尝试 10 个端口
- 前端 `api.js` 通过 `window.location.origin` 获取 base URL，不硬编码端口号

### 9.9 🔴4 IDA 子进程终止

`subprocess.Popen.kill()` 在 Windows 上只杀父进程，IDA 子进程（如 `win32_remote.exe`）会变成孤儿进程：

- `engine/orchestrator.py` 的 `stop()` 方法使用 `taskkill /F /T /PID <pid>` 递归终止整棵进程树
- `DELETE /api/scan/stop/{task_id}` 调用 `runner.stop()` 并清理临时 wrapper 脚本
- `/T` 参数是 Windows 特有的，Linux/Mac 下用 `os.killpg()`

### 9.10 🔴5 result_id 统一格式

result_id 格式必须明确，否则 B 同学（结果页）和 C 同学（LLM 审查）对接会出错：

- result_id = `"{device}/{firmware}/{path_index}"` 三段式
- `device`：固件厂商+型号（如 `ASUS_GT-AC2900`）
- `firmware`：二进制文件名（如 `cfg_server`）
- `path_index`：该漏洞 JSON 文件中 path 数组的 **1-based** 索引（如 `"3"`）
- 前端从 API 返回的 `device`、`firmware` 字段和 path 数组索引自行拼接

---

## 10. 附录：文件清单总表

| 文件 | 成员 | 操作 | 行数估算 |
|------|:----:|------|:--------:|
| `main.py` | D | 新建 | ~80 |
| `server/__init__.py` | D | 新建 | ~5 |
| `server/app.py` | D | 新建 | ~60 |
| `server/routes/__init__.py` | D | 新建 | ~5 |
| `server/routes/scan.py` | A | 新建 | ~120 |
| `server/routes/results.py` | B | 新建 | ~150 |
| `server/routes/settings.py` | C | 新建 | ~80 |
| `server/routes/llm.py` | C | 新建 | ~100 |
| `server/websocket.py` | A | 新建 | ~70 |
| `engine/__init__.py` | D | 新建 | ~3 |
| `engine/orchestrator.py` | A | 改写 run.py | ~250 |
| `engine/config_manager.py` | C | 新建 | ~80 |
| `engine/ida_detector.py` | C | 新建 | ~80 |
| `frontend/index.html` | D | 新建 | ~80 |
| `frontend/css/main.css` | D | 新建 | ~200 |
| `frontend/css/components.css` | D | 新建 | ~250 |
| `frontend/css/analysis.css` | A | 新建 | ~150 |
| `frontend/css/results.css` | B | 新建 | ~150 |
| `frontend/css/settings.css` | C | 新建 | ~120 |
| `frontend/js/app.js` | D | 新建 | ~100 |
| `frontend/js/api.js` | D | 新建 | ~80 |
| `frontend/js/components.js` | D | 新建 | ~200 |
| `frontend/js/analysis.js` | A | 新建 | ~200 |
| `frontend/js/results.js` | B | 新建 | ~180 |
| `frontend/js/settings.js` | C | 新建 | ~180 |
| `frontend/assets/icon.svg` | D | 新建 | ~1 |
| `resources/backward/*` | D | 复制 | — |
| `resources/config/config.json` | D | 复制 | — |
| `resources/llm/*` | D | 复制 | — |
| `requirements.txt` | D | 新建 | ~5 |
| `build.py` | D | 新建 | ~50 |
| `installer.nsi` | D | 新建 | ~100 |
| **总计** | | **约 30 个文件** | **~2900 行** |
