/* ============================================================
   历史记录页 — 分组视图 + 折叠 + 树形图 + 详情面板
   ============================================================ */

(function () {
  'use strict';

  var _records = [];

  // ── helpers ──────────────────────────────────────────────

  function _esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function _cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(String(value));
    return String(value).replace(/["\\]/g, '\\$&');
  }

  function _severityForCwe(cwe) {
    if (cwe === 'CWE-78') return 'critical';
    if (cwe === 'CWE-120' || cwe === 'CWE-121' || cwe === 'CWE-122') return 'high';
    return 'medium';
  }

  // ── flatten records into display items ───────────────────

  function _flatten(records) {
    var items = [];
    records.forEach(function (rec) {
      (rec.entries || []).forEach(function (e) {
        var vuln = e.vuln_info || {};
        var path = Array.isArray(vuln.path) ? vuln.path : [];
        items.push({
          result_id: e.result_id || '',
          device: rec.device || 'Unknown',
          firmware: rec.firmware || 'Unknown',
          vuln_type: vuln.vuln_type || 'CWE-N/A',
          sink_func: vuln.sink_func || 'unknown',
          source_func: vuln.source_func || 'unknown',
          path: path,
          path_index: (e.result_id || '').split('/')[2] || '?',
          path_length: path.length,
          severity: _severityForCwe(vuln.vuln_type || ''),
          decompiled_code: e.code_content || '',
          verdict: e.verdict || null,
          record_id: rec.record_id,
          llm_reviewed: rec.llm_reviewed,
        });
      });
    });
    return items;
  }

  // ── main render ──────────────────────────────────────────

  function _renderAll(records) {
    var container = document.getElementById('history-list');
    if (!container) return;

    if (!records.length) {
      container.innerHTML = '<div class="panel results-empty-panel"><div class="panel-body"><p class="code-label">NO HISTORY</p><p class="text-muted text-sm mt-sm">No history records. Save results from the <b>Results</b> page first.</p></div></div>';
      return;
    }

    var items = _flatten(records);
    var grouped = _groupResults(items);
    var fwCount = grouped.reduce(function (s, d) { return s + d.firmwares.length; }, 0);
    var summary =
      '<div class="results-summary">' +
        '<span>' + items.length + ' findings · ' + grouped.length + ' devices · ' + fwCount + ' binaries/CGI</span>' +
        '<span>History records: ' + records.length + '</span>' +
      '</div>';

    container.innerHTML = summary + grouped.map(function (g) { return _renderDeviceGroup(g, records); }).join('');
    _wireCollapse();
  }

  // ── grouping ─────────────────────────────────────────────

  function _groupResults(results) {
    var devices = {};
    results.forEach(function (item) {
      var dev = item.device || 'Unknown';
      var fw = item.firmware || 'Unknown';
      if (!devices[dev]) devices[dev] = { device: dev, firmwareMap: {}, firmwares: [] };
      if (!devices[dev].firmwareMap[fw]) {
        devices[dev].firmwareMap[fw] = { firmware: fw, results: [] };
        devices[dev].firmwares.push(devices[dev].firmwareMap[fw]);
      }
      devices[dev].firmwareMap[fw].results.push(item);
    });
    return Object.keys(devices).sort().map(function (dev) {
      devices[dev].firmwares.sort(function (a, b) { return a.firmware.localeCompare(b.firmware); });
      return devices[dev];
    });
  }

  function _renderDeviceGroup(group, records) {
    var vulnCount = group.firmwares.reduce(function (s, f) { return s + f.results.length; }, 0);
    // Find record_id for the delete button (from first result in this group)
    var recId = group.firmwares[0] && group.firmwares[0].results[0] ? group.firmwares[0].results[0].record_id : '';
    var rec = null;
    for (var i = 0; i < records.length; i++) { if (records[i].record_id === recId) { rec = records[i]; break; } }
    var reviewedTag = rec && rec.llm_reviewed ? '<span style="color:var(--accent-cyan);font-size:10px;">LLM ✓</span>' : '';

    return '<div class="panel result-device-group" data-device="' + _esc(group.device) + '">' +
      '<div class="result-device-head collapse-trigger" data-target="device-body-' + _esc(recId) + '">' +
        '<div style="display:flex;align-items:center;gap:10px;">' +
          '<span class="collapse-arrow">▼</span>' +
          '<div><span class="code-label">FIRMWARE / DEVICE</span><h2>' + _esc(group.device) + '</h2></div>' +
        '</div>' +
        '<div class="result-device-stats">' +
          '<span>' + group.firmwares.length + ' binaries/CGI</span>' +
          '<span>' + vulnCount + ' findings</span>' +
          reviewedTag +
          '<button class="btn btn-secondary btn-sm history-del-record" data-record-id="' + _esc(recId) + '" style="color:var(--danger);" title="Delete this record">Del</button>' +
        '</div>' +
      '</div>' +
      '<div class="result-firmware-groups collapse-body" id="device-body-' + _esc(recId) + '">' +
        group.firmwares.map(function (fw) { return _renderFirmwareGroup(fw); }).join('') +
      '</div>' +
    '</div>';
  }

  function _renderFirmwareGroup(group) {
    var cwes = [];
    var sinks = [];
    group.results.forEach(function (r) {
      if (cwes.indexOf(r.vuln_type) === -1) cwes.push(r.vuln_type);
      if (sinks.indexOf(r.sink_func) === -1) sinks.push(r.sink_func);
    });
    var fwId = 'fw-body-' + _esc((group.results[0] || {}).record_id || 'x') + '-' + _esc(group.firmware);

    return '<section class="result-firmware-group">' +
      '<div class="result-firmware-head collapse-trigger" data-target="' + fwId + '">' +
        '<div style="display:flex;align-items:center;gap:10px;">' +
          '<span class="collapse-arrow">▼</span>' +
          '<div><span class="code-label">BINARY / CGI</span><h3>' + _esc(group.firmware) + '</h3></div>' +
        '</div>' +
        '<div class="result-firmware-tags">' +
          '<span>' + group.results.length + ' vulns</span>' +
          '<span>' + _esc(cwes.join(', ')) + '</span>' +
          '<span>sinks: ' + _esc(sinks.join(', ')) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="collapse-body" id="' + fwId + '">' +
        _renderFirmwareTree(group) +
        '<div class="result-vuln-list">' + group.results.map(_renderCard).join('') + '</div>' +
      '</div>' +
    '</section>';
  }

  // ── real tree visualization ──────────────────────────────

  function _renderFirmwareTree(group) {
    var root = { name: group.firmware, role: 'root', children: {}, findings: [], isRoot: true };
    group.results.forEach(function (item) {
      var path = Array.isArray(item.path) ? item.path : [];
      var cursor = root;
      path.forEach(function (node, idx) {
        var label = node.label || (idx === 0 ? 'source' : (idx === path.length - 1 ? 'sink' : 'propagate'));
        var key = [node.func || 'unknown', label, node.call_ea || '', node.func_ea || '', node.arg_index == null ? '' : node.arg_index].join('|');
        if (!cursor.children[key]) {
          cursor.children[key] = { name: node.func || 'unknown', role: label, arg: node.arg_index, callEa: node.call_ea, funcEa: node.func_ea, children: {}, findings: [] };
        }
        cursor = cursor.children[key];
      });
      cursor.findings.push(item);
    });

    return '<div class="firmware-tree-wrap">' +
      '<div class="code-block-title">CGI vulnerability tree</div>' +
      '<div class="tree-root">' +
        '<div class="tree-root-label"><span>' + _esc(group.firmware) + '</span></div>' +
        _renderTreeChildren(root) +
      '</div>' +
    '</div>';
  }

  function _renderTreeChildren(node) {
    var children = Object.keys(node.children || {}).map(function (k) { return node.children[k]; });
    var allNodes = [];
    // Collect findings as leaf markers on the last real node
    children.forEach(function (child) {
      allNodes.push(child);
      // Recursively add deeper children
      var deeper = [];
      Object.keys(child.children || {}).forEach(function (k) { deeper.push(child.children[k]); });
      deeper.forEach(function (d) { allNodes.push(d); });
    });

    // Simplify: render only direct children, with nested recursion
    if (!children.length) {
      // Leaf: show findings
      var findings = node.findings || [];
      if (findings.length) {
        return '<ul class="tree-branch">' +
          findings.map(function (f) {
            return '<li class="tree-leaf">' +
              '<span class="tree-leaf-dot"></span>' +
              '<button class="tree-finding-link" data-result-id="' + _esc(f.result_id) + '">' +
                _esc((f.vuln_type || 'CWE') + ' / path #' + (f.path_index || '?')) +
              '</button>' +
            '</li>';
          }).join('') +
        '</ul>';
      }
      return '';
    }

    return '<ul class="tree-branch">' +
      children.map(function (child) {
        var rc = String(child.role || 'node').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
        var meta = [];
        if (child.arg != null) meta.push('arg ' + child.arg);
        if (child.callEa) meta.push(_esc(child.callEa));
        return '<li class="tree-node ' + rc + '">' +
          '<div class="tree-node-content">' +
            '<span class="tree-node-dot"></span>' +
            '<div class="tree-node-card">' +
              '<strong>' + _esc(child.name) + '</strong>' +
              '<span class="tree-node-role">' + _esc(child.role || 'node') + '</span>' +
              (meta.length ? '<span class="tree-node-meta">' + meta.join(' · ') + '</span>' : '') +
            '</div>' +
          '</div>' +
          _renderTreeChildren(child) +
        '</li>';
      }).join('') +
    '</ul>';
  }

  // ── cards ────────────────────────────────────────────────

  function _renderCard(item) {
    var cwe = item.vuln_type || 'CWE-N/A';
    var source = item.source_func || 'unknown';
    var sink = item.sink_func || 'unknown';
    var chain = source + ' -> ' + sink;
    var sev = item.severity || 'medium';
    var pi = item.path_index || '?';
    var vBadge = '';
    if (item.verdict) {
      var isV = item.verdict.is_vulnerable;
      vBadge = '<span class="severity-badge ' + (isV ? 'critical' : 'safe') + '" style="margin-left:6px;">' +
        (isV ? 'VULNERABLE' : 'SAFE') + '</span>';
    }

    return (
      '<div class="result-vuln-wrap">' +
      '<div class="result-card ' + sev + '" data-result-id="' + _esc(item.result_id) + '">' +
        '<div class="result-card-head">' +
          '<div class="result-title-block">' +
            '<div class="flex-row gap-sm result-meta-row">' +
              '<span class="code-label">' + _esc(item.device) + '</span>' +
              '<span class="text-xs text-muted">' + _esc(item.firmware) + '</span>' +
              '<span class="text-xs text-muted">path #' + _esc(pi) + '</span>' +
            '</div>' +
            '<div class="result-vuln-title">' + _esc(cwe) + ' — ' + _esc(sink) + '()</div>' +
            '<div class="result-facts">' +
              '<span>' + _esc(cwe) + '</span>' +
              '<span>sink: ' + _esc(sink) + '()</span>' +
              '<span>source: ' + _esc(source) + '()</span>' +
            '</div>' +
          '</div>' +
          '<div class="result-actions">' +
            '<span class="severity-badge ' + sev + '">' + sev.toUpperCase() + '</span>' +
            vBadge +
            '<button class="btn btn-secondary btn-sm result-detail-btn" data-result-id="' + _esc(item.result_id) + '">Detail</button>' +
          '</div>' +
        '</div>' +
        '<div class="result-chain">' +
          '<span class="chain-label">trigger</span>' +
          '<span class="chain-text">' + _esc(chain) + '</span>' +
        '</div>' +
        '<div class="result-extra">' +
          '<span>path length: ' + item.path_length + '</span>' +
          '<span>device: ' + _esc(item.device) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="panel result-detail-panel" data-detail-for="' + _esc(item.result_id) + '" style="display:none;"></div>' +
      '</div>'
    );
  }

  // ── detail panel ─────────────────────────────────────────

  function _showDetail(resultId) {
    if (!resultId) return;
    var sel = '.result-detail-panel[data-detail-for="' + _cssEscape(resultId) + '"]';
    var panel = document.querySelector(sel);
    if (!panel) return;
    if (panel.style.display !== 'none' && panel.dataset.loaded === 'true') {
      panel.style.display = 'none';
      return;
    }
    var items = _flatten(_records);
    var item = null;
    for (var i = 0; i < items.length; i++) {
      if (items[i].result_id === resultId) { item = items[i]; break; }
    }
    if (!item) return;

    panel.style.display = 'block';
    panel.innerHTML = _renderDetail(item);
    panel.dataset.loaded = 'true';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function _renderDetail(item) {
    var path = Array.isArray(item.path) ? item.path : [];
    var rows = path.map(function (node, idx) {
      return '<tr><td>' + (idx + 1) + '</td><td>' + _esc(node.func || '') + '</td><td>' + _esc(node.arg_index == null ? '' : node.arg_index) + '</td><td>' + _esc(node.call_ea || '') + '</td><td>' + _esc(node.func_ea || '') + '</td><td>' + _esc(node.label || '') + '</td></tr>';
    }).join('');
    var code = item.decompiled_code || '';
    var verdictHtml = '';
    if (item.verdict) {
      var v = item.verdict;
      var isV = v.is_vulnerable;
      verdictHtml =
        '<div class="detail-grid" style="margin-top:12px;">' +
          '<div><span class="code-label">LLM VERDICT</span><strong><span class="severity-badge ' + (isV ? 'critical' : 'safe') + '">' + (isV ? 'VULNERABLE' : 'SAFE') + '</span>' + (v.confidence != null ? ' (' + Math.round(v.confidence * 100) + '%)' : '') + '</strong></div>' +
          '<div style="grid-column:span 3;"><span class="code-label">REASONING</span><strong style="font-size:11px;font-weight:400;line-height:1.5;white-space:pre-wrap;">' + _esc(v.reasoning_chain || v.analysis_result || 'N/A') + '</strong></div>' +
        '</div>';
    }
    return (
      '<div class="section-hd"><span class="dot amber"></span> RESULT DETAIL</div>' +
      '<div class="panel-body result-detail-body">' +
        '<div class="detail-grid">' +
          '<div><span class="code-label">RESULT ID</span><strong>' + _esc(item.result_id) + '</strong></div>' +
          '<div><span class="code-label">CWE</span><strong>' + _esc(item.vuln_type || 'N/A') + '</strong></div>' +
          '<div><span class="code-label">SINK</span><strong>' + _esc(item.sink_func || 'N/A') + '()</strong></div>' +
          '<div><span class="code-label">SOURCE / FIRMWARE</span><strong>' + _esc((item.source_func || '?') + '()  ·  ' + item.device + '/' + item.firmware) + '</strong></div>' +
        '</div>' +
        verdictHtml +
        _renderPathTree(path) +
        '<div class="code-block-title">path hops</div>' +
        '<div class="result-path-table-wrap">' +
          '<table class="result-path-table"><thead><tr><th>#</th><th>func</th><th>arg</th><th>call_ea</th><th>func_ea</th><th>label</th></tr></thead>' +
          '<tbody>' + (rows || '<tr><td colspan="6">No path data</td></tr>') + '</tbody></table>' +
        '</div>' +
        '<div class="code-block-title">decompiled code</div>' +
        '<pre class="result-code-block">' + _esc(code || 'No decompiled code available.') + '</pre>' +
      '</div>'
    );
  }

  function _renderPathTree(path) {
    if (!Array.isArray(path) || !path.length) {
      return '<div class="code-block-title">trigger path tree</div><div class="path-tree-empty">No trigger path data</div>';
    }
    return '<div class="code-block-title">trigger path tree</div>' +
      '<div class="path-tree-wrap"><div class="path-tree">' +
        path.map(function (node, idx) {
          var label = node.label || (idx === 0 ? 'source' : (idx === path.length - 1 ? 'sink' : 'propagate'));
          var rc = String(label).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
          return '<div class="path-tree-node ' + rc + '">' +
            '<div class="path-tree-rail"><span>' + (idx + 1) + '</span></div>' +
            '<div class="path-tree-card">' +
              '<div class="path-tree-title"><strong>' + _esc(node.func || 'unknown') + '</strong><span>' + _esc(label) + '</span></div>' +
              '<div class="path-tree-meta">' +
                '<span>arg: ' + _esc(node.arg_index == null ? 'N/A' : node.arg_index) + '</span>' +
                '<span>call_ea: ' + _esc(node.call_ea || 'N/A') + '</span>' +
                '<span>func_ea: ' + _esc(node.func_ea || 'N/A') + '</span>' +
              '</div>' +
            '</div>' +
          '</div>';
        }).join('') +
      '</div></div>';
  }

  // ── collapse / expand wiring ─────────────────────────────

  function _wireCollapse() {
    document.querySelectorAll('.collapse-trigger').forEach(function (trigger) {
      trigger.addEventListener('click', function (e) {
        // Don't collapse when clicking buttons inside the header
        if (e.target.closest('button')) return;
        var targetId = trigger.dataset.target;
        var body = document.getElementById(targetId);
        if (!body) return;
        var arrow = trigger.querySelector('.collapse-arrow');
        if (body.classList.contains('collapsed')) {
          body.classList.remove('collapsed');
          if (arrow) arrow.textContent = '▼';
        } else {
          body.classList.add('collapsed');
          if (arrow) arrow.textContent = '▶';
        }
      });
    });
  }

  // ── events ───────────────────────────────────────────────

  function _handleClick(e) {
    var btn = e.target.closest('.result-detail-btn');
    var treeLink = e.target.closest('.tree-finding-link');
    if (btn || treeLink) {
      e.preventDefault();
      e.stopImmediatePropagation();
      _showDetail((btn || treeLink).dataset.resultId);
      return;
    }
    // Delete entire record
    var delRec = e.target.closest('.history-del-record');
    if (delRec) {
      e.preventDefault();
      e.stopImmediatePropagation();
      if (confirm('Delete this entire history record?')) _deleteRecord(delRec.dataset.recordId);
      return;
    }
  }

  // ── data ─────────────────────────────────────────────────

  async function _loadRecords() {
    try {
      var resp = await api.get('/api/history', { details: true });
      _records = resp.records || [];
      _renderAll(_records);
    } catch (e) {
      console.error('Failed to load history:', e);
      var c = document.getElementById('history-list');
      if (c) c.innerHTML = '<div class="panel results-empty-panel"><div class="panel-body"><p class="code-label">LOAD FAILED</p><p class="text-muted text-sm mt-sm">' + _esc(e.message) + '</p></div></div>';
    }
  }

  async function _deleteRecord(recordId) {
    try {
      await api.del('/api/history/' + recordId);
      _records = _records.filter(function (r) { return r.record_id !== recordId; });
      _renderAll(_records);
      showToast('Deleted', 'info');
    } catch (e) {
      showToast('Delete failed: ' + e.message, 'error');
    }
  }

  // ── lifecycle ────────────────────────────────────────────

  AppState.registerPage('history', {
    init: function () {
      var list = document.getElementById('history-list');
      if (list) list.addEventListener('click', _handleClick);
      _records = [];
      _loadRecords();
    },
    destroy: function () {
      var list = document.getElementById('history-list');
      if (list) list.removeEventListener('click', _handleClick);
    },
  });

})();
