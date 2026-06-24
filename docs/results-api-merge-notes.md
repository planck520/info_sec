# Results API 与分组树状结果页合并说明

> 分支：`feat/result`  
> 更新时间：2026-06-24  
> 用途：记录本次结果页相关的后端接口、前端数据结构、调试方式，方便后端联调和合并。

## 1. 本次改动文件

### 后端

- `FlashBack-GUI/server/routes/results.py`
  - 实现结果列表、结果详情、结果导出接口。
  - 从 `<output_dir>/<device>/<firmware>.json` 聚合 FlashBack 扫描结果。
  - 为前端分组树和 LLM 审查补充必要字段。
- `FlashBack-GUI/server/routes/scan.py`
  - 启动扫描时记录本次 `output_dir`。
  - 同时更新运行期 `_settings` 和持久化 `ConfigManager`。
- `FlashBack-GUI/server/routes/settings.py`
  - 增加 `output_dir` 配置项。
  - 启动时从 `ConfigManager` 读取已有配置。
  - 保存设置、检测到 IDA 路径后写入 `%APPDATA%/FlashBack/config.json`。

### 前端

- `FlashBack-GUI/frontend/js/results.js`
  - 移除 mock 扁平列表，改为读取真实 `/api/results`。
  - 按 `device -> firmware/cgi -> vulnerabilities` 分组。
  - 每个 CGI/二进制文件生成一棵聚合漏洞树。
  - 每条漏洞保留独立卡片；`Detail` 内联展开，再点一次收起。
- `FlashBack-GUI/frontend/css/results.css`
  - 增加设备组、CGI 组、聚合树、漏洞卡片、详情面板样式。
- `FlashBack-GUI/frontend/index.html`
  - 筛选下拉框占位项改为 `value=""`，避免把 `All Devices` 当真实过滤条件。
  - 静态资源加版本号，减少浏览器缓存导致的旧 JS 问题。
- `FlashBack-GUI/frontend/js/api.js`
  - `fetch` 增加 `cache: "no-store"`。
- `FlashBack-GUI/frontend/js/llm-review.js`
  - 启动 LLM 审查时随 `result_ids` 一起传当前 `output_dir`。
  - 防止多次进入结果页后重复绑定事件。

## 2. 结果 API 约定

### `GET /api/results`

查询参数：

- `device`：可选，按设备/固件组精确过滤。
- `cwe`：可选，按 CWE 精确过滤。
- `q`：可选，按 result_id、CWE、漏洞名、CVE、source、sink、trigger_chain 搜索。
- `page`：页码，默认 `1`。
- `size`：每页数量，默认 `50`，最大 `500`。
- `output_dir`：可选，显式指定扫描输出目录。

返回示例：

```json
{
  "total": 5,
  "page": 1,
  "size": 50,
  "devices": ["Tenda_AX-1806"],
  "cwes": ["CWE-120", "CWE-134", "CWE-22", "CWE-78"],
  "output_dir": "D:\\Flashback\\flashback-output-sample",
  "results": [
    {
      "result_id": "Tenda_AX-1806/tdhttpd/1",
      "device": "Tenda_AX-1806",
      "firmware": "tdhttpd",
      "path_index": 1,
      "path_length": 3,
      "vuln_type": "CWE-78",
      "vuln_name": "Command Injection Candidate",
      "cve": "CVE-SAMPLE-0001",
      "severity": "critical",
      "sink_func": "system",
      "source_func": "websGetVar",
      "param_idx": 0,
      "len_idx": null,
      "trigger_chain": ["websGetVar", "setDiagnosisCfg", "system"],
      "path": [
        {
          "func": "websGetVar",
          "arg_index": 0,
          "call_ea": "source",
          "func_ea": "source",
          "label": "source"
        }
      ]
    }
  ]
}
```

字段说明：

- `device`：来自输出路径 `<output_dir>/<device>/...`。
- `firmware`：来自 JSON 文件名 `Path.stem`，前端把它当作 CGI/二进制文件名。
- `result_id = "{device}/{firmware}/{path_index}"`，其中 `path_index` 是 1-based。
- 后端只读取符合 FlashBack 结果格式的 JSON：顶层必须是数组，且元素包含 `vuln_type`、`sink_func`、`path`。
- JSON 使用 `utf-8-sig` 读取，兼容 Windows 下带 BOM 的 UTF-8 文件。

### `GET /api/results/{result_id}`

返回单条增强结果，并额外包含：

```json
{
  "decompiled_code": "..."
}
```

详情定位规则：

- JSON 文件：`<output_dir>/<device>/<firmware>.json`
- 数组索引：`path_index - 1`
- 反编译代码候选路径：
  - `<output_dir>/<device>/<path_index>.c`
  - `<output_dir>/<device>/<firmware>_<path_index>.c`
  - `<output_dir>/<device>/<firmware>/<path_index>.c`

### `GET /api/results/export`

支持格式：

- `json`
- `csv`
- `markdown`

导出接口复用 `/api/results` 的筛选条件。

## 3. output_dir 解析顺序

后端会按以下顺序寻找扫描输出目录：

1. 请求中显式传入的 `output_dir`。
2. 运行期 `_settings["output_dir"]`。
3. `%APPDATA%/FlashBack/config.json` 中的 `output_dir`。
4. 当前进程内已有扫描任务的 `output_dir`。
5. 项目常见目录：`FlashBack-GUI/output`、`outputs`、`results`。

当前本机用于页面演示的样例目录：

```text
D:\Flashback\flashback-output-sample
```

当前本机持久化配置文件：

```text
%APPDATA%\FlashBack\config.json
```

## 4. 前端分组模型

结果页现在按以下层级渲染：

```text
固件/设备组
└── CGI/二进制文件
    ├── 当前 CGI 的聚合漏洞树
    └── 单条漏洞卡片
        └── 内联详情面板
```

字段映射：

- 一级：`device`
- 二级：`firmware`
- 三级：`result_id`

每条漏洞卡片仍然保留：

```html
.result-card[data-result-id="..."]
```

这样 LLM 审查模块仍然可以按单条结果选择。

## 5. CGI 聚合漏洞树语义

FlashBack 当前原始结果中，每条结果的 `path` 是一条 source-to-sink 候选链路：

```text
source -> intermediate node(s) -> sink
```

也就是说，单个 `result_id` 表示一条恢复出来的传播路径，不是完整调用图，也不是天然带分叉的 graph。

前端对同一个 CGI/二进制文件内的所有 `path` 做 trie 合并，生成一棵“CGI vulnerability tree”。

当前树节点 key：

```javascript
node key = func + label + call_ea + func_ea + arg_index
```

因此：

- 多条链路共享 source 时，会在 source 节点合并。
- 多条链路共享中间函数、label、地址、参数时，会在中间节点合并。
- 不同 source 会成为不同分支。
- 不同中间函数会成为不同分支。
- 每条漏洞结果会挂在该条 path 的最后一个节点上。

## 6. 多条链路最后导到同一个漏洞时，现在怎么处理

当前处理取决于链路形态：

### 情况 1：多条记录的完整 path 完全相同，最后节点也相同

树会把整条链合并。

最后节点下会出现多个 finding 链接。

### 情况 2：前缀或中间节点不同，但最后 sink/漏洞看起来相同

当前树会画成多条分支。

最后的 sink 节点会在不同分支下各出现一次。

这是因为当前展示是严格树结构，树不能天然表达“多个父节点最后汇聚到同一个子节点”的 DAG 关系。为了不误导数据语义，目前选择复制最后节点，而不是强行画交叉边。

### 情况 3：sink 函数名相同，但调用地址不同

会被当作不同节点。

原因是 `call_ea` 是节点 key 的一部分：

```text
system @ 0x4012a0
system @ 0x402210
```

这两个不应合并。

### 情况 4：人看起来像同一个漏洞，但后端没有稳定漏洞 ID

当前无法严格证明它们是同一个漏洞。

因为现在的 `result_id` 是 path-based：

```text
{device}/{firmware}/{path_index}
```

不是 vulnerability-instance-based。

如果后续希望后端和前端都能稳定识别“同一个漏洞的多条触发链路”，建议后端增加类似字段：

```json
{
  "vuln_id": "Tenda_AX-1806/tdhttpd/CWE-78/system/0x4012a0/param0",
  "sink_call_ea": "0x4012a0",
  "sink_signature": "CWE-78:system:param0:0x4012a0"
}
```

有了这个字段后，前端可以把多条 path 聚合为：

```text
CGI root
├── path A ...
├── path B ...
└── Vulnerability group: CWE-78 system @ 0x4012a0
```

或者进一步从树升级为 DAG/图视图，真实表达“多条链路汇聚到同一个漏洞”。

## 7. 本地验证命令

进入目录：

```powershell
cd D:\Flashback\info_sec\FlashBack-GUI
```

语法检查：

```powershell
.\.venv\Scripts\python.exe -m py_compile `
  server\routes\results.py `
  server\routes\scan.py `
  server\routes\settings.py

node --check frontend\js\results.js
node --check frontend\js\api.js
node --check frontend\js\llm-review.js
```

接口检查：

```powershell
Invoke-WebRequest `
  'http://127.0.0.1:18920/api/results?page=1&size=50&_=1' `
  -UseBasicParsing |
  Select-Object -ExpandProperty Content

Invoke-WebRequest `
  'http://127.0.0.1:18920/api/results/Tenda_AX-1806/tdhttpd/1?output_dir=D%3A%5CFlashback%5Cflashback-output-sample' `
  -UseBasicParsing |
  Select-Object -ExpandProperty Content
```

页面检查：

```text
http://127.0.0.1:18920/?v=20260621-5#results
```

当前样例期望结构：

```text
Tenda_AX-1806
├── cgibin
│   ├── CWE-22 / fopen
│   └── CWE-134 / printf
└── tdhttpd
    ├── CWE-78 / system
    ├── CWE-78 / popen
    └── CWE-120 / strcpy
```
