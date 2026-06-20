/* 结果页逻辑 — 成员 B 实现
   注意: result_id 格式为 {device}/{firmware}/{path_index} (1-based)
   API 字段名: vuln_type, sink_func, source_func, device, firmware, path_length

   LLM 审查功能由 LLMReview 模块提供，在页面 init/destroy 中挂载。
   当前使用 mock 数据演示 LLM 审查 UI（成员 B 完成后删除）。
*/

// ── mock data (remove when Member B delivers real API) ──
var _MOCK_RESULTS = [
  { id:'Tenda_AX-1806/tdhttpd/1',   cwe:'CWE-78',  sink:'system',   source:'websGetVar',  device:'Tenda AX-1806',   firmware:'tdhttpd',  sev:'critical' },
  { id:'Tenda_AX-1806/tdhttpd/2',   cwe:'CWE-120', sink:'strcpy',   source:'recv',         device:'Tenda AX-1806',   firmware:'tdhttpd',  sev:'high' },
  { id:'Tenda_AX-1806/tdhttpd/3',   cwe:'CWE-78',  sink:'popen',    source:'getenv',       device:'Tenda AX-1806',   firmware:'tdhttpd',  sev:'critical' },
  { id:'TOTOLINK_A7000/cgibin/1',   cwe:'CWE-120', sink:'sprintf',  source:'nvram_get',    device:'TOTOLINK A7000',  firmware:'cgibin',   sev:'high' },
  { id:'TOTOLINK_A7000/cgibin/2',   cwe:'CWE-134', sink:'printf',   source:'websGetVar',   device:'TOTOLINK A7000',  firmware:'cgibin',   sev:'medium' },
  { id:'Tenda_AX-3/httpd/1',        cwe:'CWE-78',  sink:'system',   source:'cgi_get',      device:'Tenda AX-3',      firmware:'httpd',    sev:'critical' },
  { id:'Tenda_AX-3/httpd/2',        cwe:'CWE-22',  sink:'fopen',    source:'websGetVar',   device:'Tenda AX-3',      firmware:'httpd',    sev:'medium' },
  { id:'Netgear_RAX-30/uhttpd/1',   cwe:'CWE-120', sink:'memcpy',   source:'recv',         device:'Netgear RAX-30',  firmware:'uhttpd',   sev:'high' },
];

function _renderMockResults() {
  var container = document.getElementById('results-list');
  if (!container) return;
  container.innerHTML = _MOCK_RESULTS.map(function (r) {
    return (
      '<div class="result-card ' + r.sev + '" data-result-id="' + r.id + '" style="cursor:pointer;">' +
        '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
          '<div class="flex-col gap-xs">' +
            '<div class="flex-row gap-sm" style="align-items:center;">' +
              '<span class="code-label" style="font-size:10px;">' + r.device + '</span>' +
              '<span class="text-xs text-muted">' + r.firmware + '</span>' +
            '</div>' +
            '<span class="code-value" style="font-size:14px;">' + r.cwe + ' — ' + r.sink + '()</span>' +
            '<span class="text-xs text-muted">source: ' + r.source + '()  ·  path #' + r.id.split('/')[2] + '</span>' +
          '</div>' +
          '<span class="severity-badge" style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:600;' +
            (r.sev === 'critical' ? 'background:rgba(248,113,113,0.18);color:var(--danger);' :
             r.sev === 'high'     ? 'background:rgba(251,191,36,0.18);color:var(--warning);' :
                                    'background:rgba(59,130,246,0.15);color:var(--accent);') +
            '">' + r.sev.toUpperCase() + '</span>' +
        '</div>' +
      '</div>'
    );
  }).join('');
}

AppState.registerPage('results', {
  init: function () {
    // TODO: 成员 B — 替换为真实 API 加载
    _renderMockResults();
    if (typeof LLMReview !== 'undefined') {
      LLMReview.init();
    }
  },
  destroy: function () {
    // TODO: 成员 B — 清理详情面板 DOM
    if (typeof LLMReview !== 'undefined') {
      LLMReview.destroy();
    }
  },
});
