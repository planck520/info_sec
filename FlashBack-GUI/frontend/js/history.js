/* ============================================================
   历史记录页 — 查看、展开、删除已保存的扫描结果
   详情面板：4列网格 + 路径树 + 路径表 + 反编译代码
   ============================================================ */

(function () {
  'use strict';

  var _records = [];
  var _expandedId = null;

  // ── helpers ──────────────────────────────────────────────

  function _esc(s) {
    var div = document.createElement('div');
    div.textContent = s == null ? '' : String(s);
    return div.innerHTML;
  }

  function _formatTime(iso) {
    if (!iso) return '';
    try {
      var d = new Date(iso);
      return d.toLocaleString('zh-CN', { hour12: false });
    } catch (e) { return iso; }
  }

  function _sevClass(vulnType) {
    var critical = ['CWE-78', 'CWE-94', 'CWE-502'];
    var high = ['CWE-120', 'CWE-134', 'CWE-114'];
    if (critical.indexOf(vulnType) !== -1) return 'critical';
    if (high.indexOf(vulnType) !== -1) return 'high';
    return 'medium';
  }

  // ── list rendering ───────────────────────────────────────

  function _renderList() {
    var container = document.getElementById('history-list');
    if (!container) return;

    if (!_records.length) {
      container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted);">No history records.<br><br>Save results from the <b>Results</b> page first.</div>';
      return;
    }

    container.innerHTML = _records.map(function (rec) {
      var isExpanded = _expandedId === rec.record_id;
      var reviewedTag = rec.llm_reviewed
        ? '<span style="font-weight:600;color:var(--accent-cyan);">LLM ✓</span>'
        : '<span style="color:var(--text-muted);">LLM ✗</span>';

      return (
        '<div class="history-card' + (isExpanded ? ' expanded' : '') + '" data-record-id="' + rec.record_id + '">' +
          '<div class="history-card-bar">' +
            '<div class="flex-col gap-xs" style="flex:1;min-width:0;">' +
              '<div class="flex-row gap-sm" style="align-items:center;">' +
                '<span style="font-size:14px;font-weight:600;color:#fff;">' + _esc(rec.device) + '</span>' +
                '<span class="code-label" style="font-size:10px;">' + _esc(rec.firmware) + '</span>' +
              '</div>' +
              '<div class="flex-row gap-sm">' +
                '<span class="text-xs text-muted">' + _formatTime(rec.created_at) + '</span>' +
                '<span class="text-xs text-muted">·</span>' +
                '<span class="text-xs" style="color:var(--accent);">' + rec.entry_count + ' vulns</span>' +
                '<span class="text-xs text-muted">·</span>' +
                reviewedTag +
              '</div>' +
            '</div>' +
            '<div class="flex-row gap-sm" style="flex-shrink:0;">' +
              '<button class="btn btn-secondary btn-sm" data-action="toggle" data-id="' + rec.record_id + '">' +
                (isExpanded ? 'Collapse' : 'Details') +
              '</button>' +
              '<button class="btn btn-secondary btn-sm" data-action="delete" data-id="' + rec.record_id + '" style="color:var(--danger);">Del</button>' +
            '</div>' +
          '</div>' +
          (isExpanded ? _renderDetail(rec) : '') +
        '</div>'
      );
    }).join('');
  }

  // ── detail panel ─────────────────────────────────────────

  function _renderDetail(rec) {
    if (!rec.entries || !rec.entries.length) return '';
    return (
      '<div class="history-detail">' +
        rec.entries.map(function (e, i) {
          return _renderEntryDetail(e, rec);
        }).join('') +
      '</div>'
    );
  }

  function _renderEntryDetail(e, rec) {
    var vuln = e.vuln_info || {};
    var path = Array.isArray(vuln.path) ? vuln.path : [];
    var sev = _sevClass(vuln.vuln_type || '');
    var v = e.verdict;

    // Verdict badge
    var badgeHtml = '';
    if (v) {
      var isVuln = v.is_vulnerable;
      badgeHtml = '<span class="severity-badge ' + (isVuln ? 'critical' : 'safe') + '">' +
        (isVuln ? 'VULNERABLE' : 'SAFE') +
        (v.confidence != null ? ' (' + Math.round(v.confidence * 100) + '%)' : '') +
        '</span>';
    } else {
      badgeHtml = '<span style="font-size:10px;color:var(--text-muted);">No review</span>';
    }

    // Path table rows
    var rows = path.map(function (node, idx) {
      return '<tr>' +
        '<td>' + (idx + 1) + '</td>' +
        '<td>' + _esc(node.func || '') + '</td>' +
        '<td>' + _esc(node.arg_index == null ? '' : node.arg_index) + '</td>' +
        '<td>' + _esc(node.call_ea || '') + '</td>' +
        '<td>' + _esc(node.func_ea || '') + '</td>' +
        '<td>' + _esc(node.label || '') + '</td>' +
      '</tr>';
    }).join('');

    var code = e.code_content || '';

    return (
      '<div class="history-entry">' +
        // Header row
        '<div class="flex-row gap-sm" style="align-items:center;flex-wrap:wrap;margin-bottom:10px;">' +
          '<span class="severity-badge ' + sev + '">' + sev.toUpperCase() + '</span>' +
          '<span class="code-label">' + _esc(vuln.vuln_type || '?') + '</span>' +
          '<span style="font-size:12px;color:#fff;">sink: ' + _esc(vuln.sink_func || '?') + '()</span>' +
          '<span class="text-xs text-muted">← ' + _esc(vuln.source_func || '?') + '()</span>' +
          '<span class="text-xs text-muted">· ' + path.length + ' hops</span>' +
          badgeHtml +
        '</div>' +

        // 4-column grid
        '<div class="detail-grid">' +
          '<div><span class="code-label">RESULT ID</span><strong>' + _esc(e.result_id || '') + '</strong></div>' +
          '<div><span class="code-label">CWE</span><strong>' + _esc(vuln.vuln_type || 'N/A') + '</strong></div>' +
          '<div><span class="code-label">SINK</span><strong>' + _esc(vuln.sink_func || 'N/A') + '()</strong></div>' +
          '<div><span class="code-label">SOURCE / FIRMWARE</span><strong>' + _esc((vuln.source_func || '?') + '()  ·  ' + (rec.device || '') + '/' + (rec.firmware || '')) + '</strong></div>' +
        '</div>' +

        // Path tree
        _renderPathTree(path) +

        // Path table
        '<div class="code-block-title">path hops</div>' +
        '<div class="result-path-table-wrap">' +
          '<table class="result-path-table">' +
            '<thead><tr><th>#</th><th>func</th><th>arg</th><th>call_ea</th><th>func_ea</th><th>label</th></tr></thead>' +
            '<tbody>' + (rows || '<tr><td colspan="6">No path data</td></tr>') + '</tbody>' +
          '</table>' +
        '</div>' +

        // Code block
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
      '<div class="path-tree-wrap">' +
        '<div class="path-tree">' +
          path.map(function (node, idx) {
            var label = node.label || (idx === 0 ? 'source' : (idx === path.length - 1 ? 'sink' : 'propagate'));
            var roleClass = String(label).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
            return '<div class="path-tree-node ' + roleClass + '">' +
              '<div class="path-tree-rail"><span>' + (idx + 1) + '</span></div>' +
              '<div class="path-tree-card">' +
                '<div class="path-tree-title">' +
                  '<strong>' + _esc(node.func || 'unknown') + '</strong>' +
                  '<span>' + _esc(label) + '</span>' +
                '</div>' +
                '<div class="path-tree-meta">' +
                  '<span>arg: ' + _esc(node.arg_index == null ? 'N/A' : node.arg_index) + '</span>' +
                  '<span>call_ea: ' + _esc(node.call_ea || 'N/A') + '</span>' +
                  '<span>func_ea: ' + _esc(node.func_ea || 'N/A') + '</span>' +
                '</div>' +
              '</div>' +
            '</div>';
          }).join('') +
        '</div>' +
      '</div>';
  }

  // ── data ─────────────────────────────────────────────────

  async function _loadRecords() {
    try {
      var resp = await api.get('/api/history');
      _records = resp.records || [];
      _renderList();
    } catch (e) {
      console.error('Failed to load history:', e);
    }
  }

  async function _deleteRecord(recordId) {
    try {
      await api.delete('/api/history/' + recordId);
      _records = _records.filter(function (r) { return r.record_id !== recordId; });
      if (_expandedId === recordId) _expandedId = null;
      _renderList();
      showToast('Deleted', 'info');
    } catch (e) {
      showToast('Delete failed: ' + e.message, 'error');
    }
  }

  async function _loadDetail(recordId) {
    try {
      var resp = await api.get('/api/history/' + recordId);
      var idx = -1;
      for (var i = 0; i < _records.length; i++) {
        if (_records[i].record_id === recordId) { idx = i; break; }
      }
      if (idx >= 0) _records[idx] = resp;
      _renderList();
    } catch (e) {
      showToast('Failed to load detail: ' + e.message, 'error');
    }
  }

  // ── events ───────────────────────────────────────────────

  function _handleClick(e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) {
      var bar = e.target.closest('.history-card-bar');
      if (bar) {
        var card = bar.closest('.history-card');
        if (card) {
          var rid = card.dataset.recordId;
          if (_expandedId === rid) {
            _expandedId = null;
            _renderList();
          } else {
            _expandedId = rid;
            var rec = null;
            for (var i = 0; i < _records.length; i++) {
              if (_records[i].record_id === rid) { rec = _records[i]; break; }
            }
            if (rec && rec.entries && rec.entries.length > 0 && rec.entries[0].code_content !== undefined) {
              _renderList();
            } else {
              _loadDetail(rid);
            }
          }
        }
      }
      return;
    }
    var action = btn.dataset.action;
    var id = btn.dataset.id;
    if (action === 'toggle') {
      if (_expandedId === id) {
        _expandedId = null;
        _renderList();
      } else {
        _expandedId = id;
        var rec2 = null;
        for (var j = 0; j < _records.length; j++) {
          if (_records[j].record_id === id) { rec2 = _records[j]; break; }
        }
        if (rec2 && rec2.entries && rec2.entries.length > 0 && rec2.entries[0].code_content !== undefined) {
          _renderList();
        } else {
          _loadDetail(id);
        }
      }
    } else if (action === 'delete') {
      if (confirm('Delete this record?')) _deleteRecord(id);
    }
  }

  // ── lifecycle ────────────────────────────────────────────

  AppState.registerPage('history', {
    init: function () {
      var list = document.getElementById('history-list');
      if (list) list.addEventListener('click', _handleClick);
      _loadRecords();
    },
    destroy: function () {
      var list = document.getElementById('history-list');
      if (list) list.removeEventListener('click', _handleClick);
    },
  });

})();
