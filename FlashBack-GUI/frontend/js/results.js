/* 结果页逻辑 — 读取 /api/results 真实扫描结果。 */

var ResultsPage = (function () {
  'use strict';

  var state = {
    page: 1,
    size: 50,
    total: 0,
    results: [],
    devices: [],
    cwes: [],
    outputDir: '',
    binded: false,
    searchTimer: null,
  };

  function $(id) { return document.getElementById(id); }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"]/g, function (ch) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch];
    });
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/'/g, '&#39;');
  }

  function currentParams() {
    var params = { page: state.page, size: state.size, _: Date.now() };
    var search = $('results-search');
    var device = $('results-device-filter');
    var cwe = $('results-cwe-filter');
    if (search && search.value.trim()) params.q = search.value.trim();
    if (device && device.value && device.value !== 'All Devices') params.device = device.value;
    if (cwe && cwe.value && cwe.value !== 'All CWE Types') params.cwe = cwe.value;
    if (state.outputDir) params.output_dir = state.outputDir;
    return params;
  }

  async function loadResults() {
    renderLoading();
    try {
      var data = await api.get('/api/results', currentParams());
      state.total = data.total || 0;
      state.results = data.results || [];
      state.devices = data.devices || [];
      state.cwes = data.cwes || [];
      state.outputDir = data.output_dir || state.outputDir || '';
      populateFilters();
      renderResults(data.message || '');
    } catch (err) {
      renderError(err.message);
    }
  }

  function populateFilters() {
    fillSelect('results-device-filter', 'All Devices', state.devices);
    fillSelect('results-cwe-filter', 'All CWE Types', state.cwes);
  }

  function fillSelect(id, label, values) {
    var select = $(id);
    if (!select) return;
    var previous = select.value;
    select.innerHTML = '<option value="">' + escapeHtml(label) + '</option>' +
      values.map(function (value) {
        return '<option value="' + escapeAttr(value) + '">' + escapeHtml(value) + '</option>';
      }).join('');
    if (values.indexOf(previous) !== -1) select.value = previous;
  }

  function renderLoading() {
    var container = $('results-list');
    if (!container) return;
    container.innerHTML =
      '<div class="panel results-empty-panel">' +
        '<div class="panel-body">' +
          '<p class="code-label">LOADING</p>' +
          '<p class="text-muted text-sm mt-sm">正在读取扫描结果...</p>' +
        '</div>' +
      '</div>';
  }

  function renderError(message) {
    var container = $('results-list');
    if (!container) return;
    container.innerHTML =
      '<div class="panel results-empty-panel">' +
        '<div class="panel-body">' +
          '<p class="code-label">LOAD FAILED</p>' +
          '<p class="text-muted text-sm mt-sm">' + escapeHtml(message) + '</p>' +
        '</div>' +
      '</div>';
  }

  function renderResults(message) {
    var container = $('results-list');
    if (!container) return;
    if (!state.results.length) {
      container.innerHTML =
        '<div class="panel results-empty-panel">' +
          '<div class="panel-body">' +
            '<p class="code-label">NO RESULTS</p>' +
            '<p class="text-muted text-sm mt-sm">' + escapeHtml(message || '尚未发现可展示的漏洞结果。请先运行固件分析，或确认输出目录中存在 <device>/<firmware>.json。') + '</p>' +
          '</div>' +
        '</div>';
      return;
    }

    var grouped = groupResults(state.results);
    var firmwareCount = grouped.reduce(function (sum, deviceGroup) {
      return sum + deviceGroup.firmwares.length;
    }, 0);
    var summary =
      '<div class="results-summary">' +
        '<span>' + state.total + ' findings · ' + grouped.length + ' firmware groups · ' + firmwareCount + ' binaries/CGI</span>' +
        '<span>' + (state.outputDir ? escapeHtml(state.outputDir) : 'output_dir not set') + '</span>' +
      '</div>';

    container.innerHTML = summary + grouped.map(renderDeviceGroup).join('');
  }

  function groupResults(results) {
    var devices = {};
    results.forEach(function (item) {
      var device = item.device || 'Unknown Firmware';
      var firmware = item.firmware || 'Unknown CGI';
      if (!devices[device]) devices[device] = { device: device, firmwareMap: {}, firmwares: [] };
      if (!devices[device].firmwareMap[firmware]) {
        var group = { firmware: firmware, results: [] };
        devices[device].firmwareMap[firmware] = group;
        devices[device].firmwares.push(group);
      }
      devices[device].firmwareMap[firmware].results.push(item);
    });
    return Object.keys(devices).sort().map(function (device) {
      devices[device].firmwares.sort(function (a, b) { return a.firmware.localeCompare(b.firmware); });
      return devices[device];
    });
  }

  function renderDeviceGroup(group) {
    var vulnCount = group.firmwares.reduce(function (sum, fw) { return sum + fw.results.length; }, 0);
    return '<div class="panel result-device-group">' +
      '<div class="result-device-head">' +
        '<div>' +
          '<span class="code-label">FIRMWARE / DEVICE</span>' +
          '<h2>' + escapeHtml(group.device) + '</h2>' +
        '</div>' +
        '<div class="result-device-stats">' +
          '<span>' + group.firmwares.length + ' binaries/CGI</span>' +
          '<span>' + vulnCount + ' findings</span>' +
        '</div>' +
      '</div>' +
      '<div class="result-firmware-groups">' +
        group.firmwares.map(renderFirmwareGroup).join('') +
      '</div>' +
    '</div>';
  }

  function renderFirmwareGroup(group) {
    var cwes = Array.from(new Set(group.results.map(function (item) { return item.vuln_type || 'CWE-N/A'; })));
    var sinks = Array.from(new Set(group.results.map(function (item) { return item.sink_func || 'unknown'; })));
    return '<section class="result-firmware-group">' +
      '<div class="result-firmware-head">' +
        '<div>' +
          '<span class="code-label">BINARY / CGI</span>' +
          '<h3>' + escapeHtml(group.firmware) + '</h3>' +
        '</div>' +
        '<div class="result-firmware-tags">' +
          '<span>' + group.results.length + ' vulnerabilities</span>' +
          '<span>' + escapeHtml(cwes.join(', ')) + '</span>' +
          '<span>sinks: ' + escapeHtml(sinks.join(', ')) + '</span>' +
        '</div>' +
      '</div>' +
      renderFirmwareTree(group) +
      '<div class="result-vuln-list">' +
        group.results.map(renderCard).join('') +
      '</div>' +
    '</section>';
  }

  function renderCard(item) {
    var cwe = item.vuln_type || 'CWE-N/A';
    var cve = item.cve || 'N/A';
    var vulnName = item.vuln_name || cwe;
    var source = item.source_func || 'unknown';
    var sink = item.sink_func || 'unknown';
    var chain = (item.trigger_chain && item.trigger_chain.length)
      ? item.trigger_chain.join(' -> ')
      : source + ' -> ' + sink;
    var severity = item.severity || severityForCwe(cwe);
    var pathIndex = item.path_index || (item.result_id || '').split('/')[2] || '?';

    return (
      '<div class="result-vuln-wrap">' +
      '<div class="result-card ' + escapeAttr(severity) + '" data-result-id="' + escapeAttr(item.result_id) + '">' +
        '<div class="result-card-head">' +
          '<div class="result-title-block">' +
            '<div class="flex-row gap-sm result-meta-row">' +
              '<span class="code-label">' + escapeHtml(item.device || 'device') + '</span>' +
              '<span class="text-xs text-muted">' + escapeHtml(item.firmware || 'firmware') + '</span>' +
              '<span class="text-xs text-muted">path #' + escapeHtml(pathIndex) + '</span>' +
            '</div>' +
            '<div class="result-vuln-title">' + escapeHtml(vulnName) + '</div>' +
            '<div class="result-facts">' +
              '<span>' + escapeHtml(cwe) + '</span>' +
              '<span>CVE: ' + escapeHtml(cve) + '</span>' +
              '<span>sink: ' + escapeHtml(sink) + '()</span>' +
              '<span>source: ' + escapeHtml(source) + '()</span>' +
            '</div>' +
          '</div>' +
          '<div class="result-actions">' +
            '<span class="severity-badge ' + escapeAttr(severity) + '">' + escapeHtml(severity.toUpperCase()) + '</span>' +
            '<button class="btn btn-secondary btn-sm result-detail-btn" data-result-id="' + escapeAttr(item.result_id) + '">Detail</button>' +
          '</div>' +
        '</div>' +
        '<div class="result-chain">' +
          '<span class="chain-label">trigger</span>' +
          '<span class="chain-text">' + escapeHtml(chain) + '</span>' +
        '</div>' +
        '<div class="result-extra">' +
          '<span>path length: ' + escapeHtml(item.path_length || 0) + '</span>' +
          '<span>param_idx: ' + escapeHtml(item.param_idx == null ? 'N/A' : item.param_idx) + '</span>' +
          '<span>len_idx: ' + escapeHtml(item.len_idx == null ? 'N/A' : item.len_idx) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="panel result-detail-panel" data-detail-for="' + escapeAttr(item.result_id) + '" style="display:none;"></div>' +
      '</div>'
    );
  }

  function renderFirmwareTree(group) {
    var root = { name: group.firmware, role: 'root', children: {}, findings: [] };
    group.results.forEach(function (item) {
      var path = Array.isArray(item.path) ? item.path : [];
      var cursor = root;
      path.forEach(function (node, idx) {
        var label = node.label || (idx === 0 ? 'source' : (idx === path.length - 1 ? 'sink' : 'propagate'));
        var key = [
          node.func || 'unknown',
          label,
          node.call_ea || '',
          node.func_ea || '',
          node.arg_index == null ? '' : node.arg_index,
        ].join('|');
        if (!cursor.children[key]) {
          cursor.children[key] = {
            name: node.func || 'unknown',
            role: label,
            arg: node.arg_index,
            callEa: node.call_ea,
            funcEa: node.func_ea,
            children: {},
            findings: [],
          };
        }
        cursor = cursor.children[key];
      });
      cursor.findings.push(item);
    });

    return '<div class="firmware-tree-wrap">' +
      '<div class="code-block-title">CGI vulnerability tree</div>' +
      '<div class="firmware-tree">' + renderTreeNode(root, 0) + '</div>' +
    '</div>';
  }

  function renderTreeNode(node, depth) {
    var childNodes = Object.keys(node.children || {}).map(function (key) { return node.children[key]; });
    var roleClass = String(node.role || 'node').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    var findings = node.findings || [];
    var meta = [];
    if (node.arg != null) meta.push('arg ' + node.arg);
    if (node.callEa) meta.push('call ' + node.callEa);
    if (node.funcEa) meta.push('func ' + node.funcEa);
    if (findings.length) meta.push(findings.length + ' finding' + (findings.length > 1 ? 's' : ''));

    return '<div class="firmware-tree-node depth-' + depth + ' ' + escapeAttr(roleClass) + '">' +
      '<div class="firmware-tree-row">' +
        '<span class="tree-joint"></span>' +
        '<span class="tree-role">' + escapeHtml(node.role || 'node') + '</span>' +
        '<strong>' + escapeHtml(node.name || 'unknown') + '</strong>' +
        (meta.length ? '<span class="tree-meta">' + escapeHtml(meta.join(' · ')) + '</span>' : '') +
      '</div>' +
      (findings.length ? '<div class="tree-findings">' + findings.map(function (item) {
        return '<button class="tree-finding-link" data-result-id="' + escapeAttr(item.result_id) + '">' +
          escapeHtml((item.vuln_type || 'CWE') + ' / ' + (item.sink_func || 'sink') + ' / path #' + (item.path_index || '?')) +
        '</button>';
      }).join('') + '</div>' : '') +
      (childNodes.length ? '<div class="firmware-tree-children">' + childNodes.map(function (child) {
        return renderTreeNode(child, depth + 1);
      }).join('') + '</div>' : '') +
    '</div>';
  }

  function severityForCwe(cwe) {
    if (cwe === 'CWE-78') return 'critical';
    if (cwe === 'CWE-120' || cwe === 'CWE-121' || cwe === 'CWE-122') return 'high';
    return 'medium';
  }

  async function showDetail(resultId) {
    if (!resultId) return;
    var selector = '.result-detail-panel[data-detail-for="' + cssEscape(resultId) + '"]';
    var panel = document.querySelector(selector);
    if (!panel) return;
    if (panel.style.display !== 'none' && panel.dataset.loaded === 'true') {
      panel.style.display = 'none';
      return;
    }
    panel.style.display = 'block';
    panel.innerHTML = '<div class="panel-body"><p class="code-label">DETAIL</p><p class="text-muted text-sm mt-sm">Loading...</p></div>';
    try {
      var path = '/api/results/' + resultId.split('/').map(encodeURIComponent).join('/');
      var params = state.outputDir ? { output_dir: state.outputDir } : null;
      var detail = await api.get(path, params);
      panel.innerHTML = renderDetail(detail);
      panel.dataset.loaded = 'true';
      panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
      panel.innerHTML = '<div class="panel-body"><p class="code-label">DETAIL FAILED</p><p class="text-muted text-sm mt-sm">' + escapeHtml(err.message) + '</p></div>';
    }
  }

  function cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(value);
    return String(value).replace(/["\\]/g, '\\$&');
  }

  function renderDetail(detail) {
    var path = Array.isArray(detail.path) ? detail.path : [];
    var rows = path.map(function (node, idx) {
      return '<tr>' +
        '<td>' + (idx + 1) + '</td>' +
        '<td>' + escapeHtml(node.func || '') + '</td>' +
        '<td>' + escapeHtml(node.arg_index == null ? '' : node.arg_index) + '</td>' +
        '<td>' + escapeHtml(node.call_ea || '') + '</td>' +
        '<td>' + escapeHtml(node.func_ea || '') + '</td>' +
        '<td>' + escapeHtml(node.label || '') + '</td>' +
      '</tr>';
    }).join('');

    var code = detail.decompiled_code || '';
    return (
      '<div class="section-hd"><span class="dot amber"></span> RESULT DETAIL</div>' +
      '<div class="panel-body result-detail-body">' +
        '<div class="detail-grid">' +
          '<div><span class="code-label">RESULT ID</span><strong>' + escapeHtml(detail.result_id) + '</strong></div>' +
          '<div><span class="code-label">VULNERABILITY</span><strong>' + escapeHtml(detail.vuln_name || detail.vuln_type || 'N/A') + '</strong></div>' +
          '<div><span class="code-label">CVE</span><strong>' + escapeHtml(detail.cve || 'N/A') + '</strong></div>' +
          '<div><span class="code-label">FIRMWARE</span><strong>' + escapeHtml((detail.device || '') + '/' + (detail.firmware || '')) + '</strong></div>' +
        '</div>' +
        renderPathTree(path) +
        '<div class="result-path-table-wrap">' +
          '<table class="result-path-table">' +
            '<thead><tr><th>#</th><th>func</th><th>arg</th><th>call_ea</th><th>func_ea</th><th>label</th></tr></thead>' +
            '<tbody>' + (rows || '<tr><td colspan="6">No path data</td></tr>') + '</tbody>' +
          '</table>' +
        '</div>' +
        '<div class="code-block-title">decompiled code</div>' +
        '<pre class="result-code-block">' + escapeHtml(code || 'No decompiled code file was found for this path.') + '</pre>' +
      '</div>'
    );
  }

  function renderPathTree(path) {
    if (!Array.isArray(path) || !path.length) {
      return '<div class="path-tree-empty">No trigger path data</div>';
    }
    return '<div class="path-tree-wrap">' +
      '<div class="code-block-title">trigger path tree</div>' +
      '<div class="path-tree">' +
        path.map(function (node, idx) {
          var label = node.label || (idx === 0 ? 'source' : (idx === path.length - 1 ? 'sink' : 'propagate'));
          var roleClass = String(label).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
          return '<div class="path-tree-node ' + escapeAttr(roleClass) + '">' +
            '<div class="path-tree-rail"><span>' + (idx + 1) + '</span></div>' +
            '<div class="path-tree-card">' +
              '<div class="path-tree-title">' +
                '<strong>' + escapeHtml(node.func || 'unknown') + '</strong>' +
                '<span>' + escapeHtml(label) + '</span>' +
              '</div>' +
              '<div class="path-tree-meta">' +
                '<span>arg: ' + escapeHtml(node.arg_index == null ? 'N/A' : node.arg_index) + '</span>' +
                '<span>call_ea: ' + escapeHtml(node.call_ea || 'N/A') + '</span>' +
                '<span>func_ea: ' + escapeHtml(node.func_ea || 'N/A') + '</span>' +
              '</div>' +
            '</div>' +
          '</div>';
        }).join('') +
      '</div>' +
      '<div class="path-tree-note">Current backend result is a single recovered path. Branching can be shown when the result schema provides child edges or grouped paths.</div>' +
    '</div>';
  }

  function bindEvents() {
    if (state.binded) return;
    state.binded = true;

    var search = $('results-search');
    var device = $('results-device-filter');
    var cwe = $('results-cwe-filter');
    var exportBtn = $('results-export-btn');
    var list = $('results-list');

    if (search) {
      search.addEventListener('input', function () {
        clearTimeout(state.searchTimer);
        state.searchTimer = setTimeout(function () {
          state.page = 1;
          loadResults();
        }, 250);
      });
    }
    if (device) device.addEventListener('change', function () { state.page = 1; loadResults(); });
    if (cwe) cwe.addEventListener('change', function () { state.page = 1; loadResults(); });
    if (exportBtn) exportBtn.addEventListener('click', exportResults);
    if (list) {
      list.addEventListener('click', function (event) {
        var btn = event.target.closest('.result-detail-btn');
        var treeLink = event.target.closest('.tree-finding-link');
        if (!btn && !treeLink) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        showDetail((btn || treeLink).dataset.resultId);
      });
    }
  }

  async function exportResults() {
    try {
      var params = currentParams();
      params.format = 'json';
      delete params.page;
      delete params.size;
      var blob = await api.get('/api/results/export', params);
      var url = URL.createObjectURL(blob);
      var link = document.createElement('a');
      link.href = url;
      link.download = 'flashback-results.json';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast('导出失败：' + err.message, 'error', 5000);
    }
  }

  function init() {
    bindEvents();
    loadResults();
    if (typeof LLMReview !== 'undefined') {
      LLMReview.init();
    }
  }

  function destroy() {
    if (state.searchTimer) clearTimeout(state.searchTimer);
    if (typeof LLMReview !== 'undefined') {
      LLMReview.destroy();
    }
  }

  return {
    init: init,
    destroy: destroy,
    reload: loadResults,
    getOutputDir: function () { return state.outputDir; },
  };
})();

AppState.registerPage('results', {
  init: ResultsPage.init,
  destroy: ResultsPage.destroy,
});
