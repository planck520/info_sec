/* ============================================================
   历史记录页 — 查看、展开、删除已保存的扫描结果
   ============================================================ */

(function () {
  'use strict';

  var _records = [];
  var _expandedId = null;

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

  function _renderDetail(rec) {
    if (!rec.entries || !rec.entries.length) return '';
    return (
      '<div class="history-detail">' +
        rec.entries.map(function (e, i) {
          var v = e.verdict;
          var badgeHtml = '';
          if (v) {
            var isVuln = v.is_vulnerable;
            badgeHtml = '<span class="llm-badge ' + (isVuln ? 'vulnerable' : 'safe') + '" style="font-size:10px;padding:2px 8px;">' +
              (isVuln ? 'VULNERABLE' : 'SAFE') +
              (v.confidence != null ? ' (' + Math.round(v.confidence * 100) + '%)' : '') +
              '</span>';
          } else {
            badgeHtml = '<span style="font-size:10px;color:var(--text-muted);">No review</span>';
          }
          var vuln = e.vuln_info || {};
          var sev = _sevClass(vuln.vuln_type || '');
          return (
            '<div class="history-entry">' +
              '<div class="flex-row gap-sm" style="align-items:center;flex-wrap:wrap;">' +
                '<span class="severity-badge" style="font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(248,113,113,0.18);color:var(--danger);' + (sev === 'high' ? 'background:rgba(251,191,36,0.18);color:var(--warning);' : '') + (sev === 'medium' ? 'background:rgba(59,130,246,0.15);color:var(--accent);' : '') + '">' + sev.toUpperCase() + '</span>' +
                '<span class="code-label">' + _esc(vuln.vuln_type || '?') + '</span>' +
                '<span style="font-size:12px;color:#fff;">sink: ' + _esc(vuln.sink_func || '?') + '()</span>' +
                '<span class="text-xs text-muted">← ' + _esc(vuln.source_func || '?') + '()</span>' +
                '<span class="text-xs text-muted">· ' + ((vuln.path || []).length) + ' hops</span>' +
                badgeHtml +
              '</div>' +
              (e.code_content ? '<pre class="history-code">' + _esc(e.code_content).substring(0, 2000) + (e.code_content.length > 2000 ? '\n... (truncated)' : '') + '</pre>' : '') +
            '</div>'
          );
        }).join('') +
      '</div>'
    );
  }

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
      // Replace summary with full detail in _records
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

  // ── event delegation ─────────────────────────────────────

  function _handleClick(e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) {
      // Click on card bar → toggle expand
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
            // Load full detail if not yet loaded
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

  function _esc(s) {
    var div = document.createElement('div');
    div.textContent = s || '';
    return div.innerHTML;
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
