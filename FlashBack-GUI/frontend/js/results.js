/* ============================================================
   结果页逻辑 — 从扫描输出目录加载真实结果
   result_id 格式: {device}/{firmware}/{path_index} (1-based)

   LLM 审查功能由 LLMReview 模块提供，在页面 init/destroy 中挂载。
   ============================================================ */

(function () {
  'use strict';

  var _results = [];
  var _outputDir = '';
  var _taskId = '';
  var _firmwareName = '';
  var _initialized = false;

  // ── detail panel (simple: no path tree, just info + code) ──

  async function _showResultDetail(resultId) {
    if (!_taskId || !resultId) return;
    var sel = '.result-detail-panel[data-detail-for="' + resultId + '"]';
    var panel = document.querySelector(sel);
    if (!panel) return;
    if (panel.style.display !== 'none' && panel.dataset.loaded === 'true') {
      panel.style.display = 'none';
      return;
    }
    panel.style.display = 'block';
    panel.innerHTML = '<div class="panel-body"><p class="code-label">DETAIL</p><p class="text-muted text-sm mt-sm">Loading...</p></div>';
    try {
      var resp = await api.get('/api/results/detail', { result_id: resultId, task_id: _taskId });
      var v = resp.vuln_info || {};
      var path = Array.isArray(v.path) ? v.path : [];
      var rows = path.map(function (node, idx) {
        return '<tr><td>' + (idx + 1) + '</td><td>' + _esc(node.func || '') + '</td><td>' + _esc(node.arg_index == null ? '' : node.arg_index) + '</td><td>' + _esc(node.call_ea || '') + '</td><td>' + _esc(node.func_ea || '') + '</td><td>' + _esc(node.label || '') + '</td></tr>';
      }).join('');
      var code = resp.code_content || '';
      panel.innerHTML =
        '<div class="section-hd"><span class="dot amber"></span> RESULT DETAIL</div>' +
        '<div class="panel-body result-detail-body">' +
          '<div class="detail-grid">' +
            '<div><span class="code-label">RESULT ID</span><strong>' + _esc(resultId) + '</strong></div>' +
            '<div><span class="code-label">CWE</span><strong>' + _esc(v.vuln_type || 'N/A') + '</strong></div>' +
            '<div><span class="code-label">SINK</span><strong>' + _esc(v.sink_func || 'N/A') + '()</strong></div>' +
            '<div><span class="code-label">SOURCE</span><strong>' + _esc(v.source_func || 'N/A') + '()</strong></div>' +
          '</div>' +
          '<div class="code-block-title">path hops</div>' +
          '<div class="result-path-table-wrap">' +
            '<table class="result-path-table"><thead><tr><th>#</th><th>func</th><th>arg</th><th>call_ea</th><th>func_ea</th><th>label</th></tr></thead>' +
            '<tbody>' + (rows || '<tr><td colspan="6">No path data</td></tr>') + '</tbody></table>' +
          '</div>' +
          '<div class="code-block-title">decompiled code</div>' +
          '<pre class="result-code-block">' + _esc(code || 'No decompiled code available.') + '</pre>' +
        '</div>';
      panel.dataset.loaded = 'true';
    } catch (e) {
      panel.innerHTML = '<div class="panel-body"><p class="code-label">DETAIL FAILED</p><p class="text-muted text-sm mt-sm">' + _esc(e.message) + '</p></div>';
    }
  }

  // ── history save helpers ────────────────────────────────

  function _removeResults(idsToRemove) {
    var removeSet = {};
    idsToRemove.forEach(function (id) { removeSet[id] = true; });
    _results = _results.filter(function (r) { return !removeSet[r.id]; });
    _applyFilters();  // preserve active filters
    if (typeof LLMReview !== 'undefined' && LLMReview.clearSelection) {
      LLMReview.clearSelection();
    }
  }

  async function saveSelected() {
    var selected = [];
    document.querySelectorAll('.result-card.selected[data-result-id]').forEach(function (c) {
      selected.push(c.dataset.resultId);
    });
    if (!selected.length) {
      showToast('Select at least one result', 'warning');
      return;
    }
    _showSaveDialog(selected);
  }

  function _showSaveDialog(selected) {
    // Fetch existing records for the dialog
    api.get('/api/history').then(function (resp) {
      _renderSaveDialog(selected, resp.records || []);
    }).catch(function () {
      _renderSaveDialog(selected, []);
    });
  }

  function _renderSaveDialog(selected, records) {
    // Remove old dialog if exists
    var old = document.getElementById('save-history-dialog');
    if (old) old.remove();

    var backdrop = document.createElement('div');
    backdrop.id = 'save-history-dialog';
    backdrop.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.65);z-index:9999;display:flex;align-items:center;justify-content:center;';

    var recordOptions = records.map(function (r) {
      return '<div class="save-dialog-record" data-record-id="' + r.record_id + '" style="padding:10px 14px;border:1px solid rgba(255,255,255,0.12);border-radius:8px;cursor:pointer;margin-bottom:6px;transition:all 0.15s;">' +
        '<span style="font-weight:600;color:#fff;">' + _esc(r.device || '?') + '</span>' +
        '<span style="color:var(--text-muted);margin-left:8px;font-size:12px;">' + _esc(r.firmware || '?') + '</span>' +
        '<span style="color:var(--text-muted);margin-left:8px;font-size:11px;">' + r.entry_count + ' vulns</span>' +
        (r.llm_reviewed ? '<span style="color:var(--accent-cyan);margin-left:6px;font-size:10px;">LLM ✓</span>' : '') +
      '</div>';
    }).join('');

    backdrop.innerHTML = '<div style="background:#1a1a2e;border:1px solid rgba(255,255,255,0.2);border-radius:16px;padding:24px;width:480px;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.5);">' +
      '<div style="font-size:16px;font-weight:700;color:#fff;margin-bottom:4px;">Save to History</div>' +
      '<div style="font-size:12px;color:var(--text-muted);margin-bottom:16px;">' + selected.length + ' result(s) selected</div>' +

      '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">Existing Records — click to append</div>' +
      '<div id="save-dialog-records" style="max-height:200px;overflow-y:auto;margin-bottom:16px;">' +
        (records.length ? recordOptions : '<div style="color:var(--text-muted);font-size:12px;padding:8px;">No existing records</div>') +
      '</div>' +

      '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">Or create new record</div>' +
      '<div class="flex-col gap-sm" style="margin-bottom:6px;">' +
        '<input id="save-dialog-device" class="input" placeholder="Device name (e.g. TOTOLINK C835BR)" style="width:100%;">' +
        '<span class="text-xs text-muted">Firmware: <b>' + _esc(_firmwareName || 'auto-detected') + '</b> (auto-detected from scan)</span>' +
      '</div>' +

      '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px;">' +
        '<button class="btn btn-secondary btn-sm" id="save-dialog-cancel">Cancel</button>' +
        '<button class="btn btn-primary btn-sm" id="save-dialog-new">Save</button>' +
      '</div>' +
    '</div>';

    document.body.appendChild(backdrop);

    var selectedRecordId = null;

    // Click backdrop to close
    backdrop.addEventListener('click', function (e) {
      if (e.target === backdrop) backdrop.remove();
    });

    // Cancel
    document.getElementById('save-dialog-cancel').addEventListener('click', function () { backdrop.remove(); });

    // Select existing record
    var recordDivs = backdrop.querySelectorAll('.save-dialog-record');
    recordDivs.forEach(function (div) {
      div.addEventListener('click', function () {
        recordDivs.forEach(function (d) { d.style.borderColor = 'rgba(255,255,255,0.12)'; d.style.background = ''; });
        div.style.borderColor = 'rgba(59,130,246,0.6)';
        div.style.background = 'rgba(59,130,246,0.1)';
        selectedRecordId = div.dataset.recordId;
      });
      div.addEventListener('mouseenter', function () {
        if (selectedRecordId !== div.dataset.recordId) div.style.background = 'rgba(255,255,255,0.04)';
      });
      div.addEventListener('mouseleave', function () {
        if (selectedRecordId !== div.dataset.recordId) div.style.background = '';
      });
    });

    // Create new
    document.getElementById('save-dialog-new').addEventListener('click', async function () {
      var device = document.getElementById('save-dialog-device').value.trim();
      if (!device && !selectedRecordId) {
        showToast('Select a record or enter a device name', 'warning');
        return;
      }
      backdrop.remove();
      await _doSave(selected, selectedRecordId || null, device, _firmwareName);
    });
  }

  async function _doSave(selected, recordId, device, firmware) {
    var verdicts = (typeof LLMReview !== 'undefined' && LLMReview.getVerdicts)
      ? LLMReview.getVerdicts() : {};
    var payload = { task_id: _taskId, result_ids: selected, verdicts: verdicts };
    if (recordId) payload.record_id = recordId;
    if (device) payload.device = device;
    if (firmware) payload.firmware = firmware;
    try {
      await api.post('/api/history', payload);
      _removeResults(selected);
      showToast('Saved ' + selected.length + ' to history', 'success');
    } catch (e) {
      showToast('Save failed: ' + e.message, 'error');
    }
  }

  function _esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function deleteSelected() {
    var selected = [];
    document.querySelectorAll('.result-card.selected[data-result-id]').forEach(function (c) {
      selected.push(c.dataset.resultId);
    });
    if (!selected.length) {
      showToast('Select at least one result', 'warning');
      return;
    }
    _removeResults(selected);
    showToast('Deleted ' + selected.length, 'info');
  }

  async function autoSaveRemaining() {
    if (!_results.length || !_taskId) return;
    var ids = _results.map(function (r) { return r.id; });
    var verdicts = (typeof LLMReview !== 'undefined' && LLMReview.getVerdicts)
      ? LLMReview.getVerdicts() : {};
    try {
      await api.post('/api/history', {
        task_id: _taskId,
        result_ids: ids,
        verdicts: verdicts,
      });
      _results = [];
    } catch (e) {
      console.error('Auto-save failed:', e);
      // Keep results — they'll be retried on next auto-save trigger
    }
  }

  function getRemainingIds() {
    return _results.map(function (r) { return r.id; });
  }

  function _renderResults(list) {
    var container = document.getElementById('results-list');
    if (!container) return;

    if (!list.length) {
      container.innerHTML = '<div class="text-muted" style="padding:40px;text-align:center;">No results. Run a scan first.</div>';
      return;
    }

    container.innerHTML = list.map(function (r) {
      var sevStyle = '';
      if (r.sev === 'critical') {
        sevStyle = 'background:rgba(248,113,113,0.18);color:var(--danger);';
      } else if (r.sev === 'high') {
        sevStyle = 'background:rgba(251,191,36,0.18);color:var(--warning);';
      } else {
        sevStyle = 'background:rgba(59,130,246,0.15);color:var(--accent);';
      }
      return (
        '<div class="result-vuln-wrap">' +
        '<div class="result-card ' + r.sev + '" data-result-id="' + r.id + '" style="cursor:pointer;">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
            '<div class="flex-col gap-xs" style="flex:1;min-width:0;">' +
              '<div class="flex-row gap-sm" style="align-items:center;">' +
                '<span class="code-label" style="font-size:10px;">' + r.device + '</span>' +
                '<span class="text-xs text-muted">' + r.firmware + '</span>' +
                '<span class="text-xs text-muted">· ' + r.path_length + ' hops</span>' +
              '</div>' +
              '<span class="code-value" style="font-size:14px;">' + r.cwe + ' — ' + r.sink + '()</span>' +
              '<span class="text-xs text-muted">source: ' + r.source + '()  ·  path #' + r.id.split('/')[2] + '</span>' +
            '</div>' +
            '<div class="flex-row gap-sm" style="flex-shrink:0;align-items:center;">' +
              '<span class="severity-badge" style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:600;' + sevStyle + '">' +
                r.sev.toUpperCase() +
              '</span>' +
              '<button class="btn btn-secondary btn-sm result-detail-btn" data-result-id="' + r.id + '">Detail</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="panel result-detail-panel" data-detail-for="' + r.id + '" style="display:none;"></div>' +
        '</div>'
      );
    }).join('');

    // Reapply LLM verdict badges (cards regenerated, verdicts persist in LLMReview)
    if (typeof LLMReview !== 'undefined' && LLMReview.reapplyVerdicts) {
      setTimeout(function () { LLMReview.reapplyVerdicts(); }, 50);
    }
  }

  function _populateFilters(list) {
    // Device filter
    var devFilter = document.getElementById('results-device-filter');
    if (devFilter) {
      var devices = [];
      list.forEach(function (r) { if (devices.indexOf(r.device) === -1) devices.push(r.device); });
      devices.sort();
      devFilter.innerHTML = '<option>All Devices</option>' +
        devices.map(function (d) { return '<option>' + d + '</option>'; }).join('');
    }

    // CWE filter
    var cweFilter = document.getElementById('results-cwe-filter');
    if (cweFilter) {
      var cwes = [];
      list.forEach(function (r) { if (cwes.indexOf(r.cwe) === -1) cwes.push(r.cwe); });
      cwes.sort();
      cweFilter.innerHTML = '<option>All CWE Types</option>' +
        cwes.map(function (c) { return '<option>' + c + '</option>'; }).join('');
    }
  }

  function _applyFilters() {
    var devFilter = document.getElementById('results-device-filter');
    var cweFilter = document.getElementById('results-cwe-filter');
    var searchInput = document.getElementById('results-search');

    var devVal = devFilter ? devFilter.value : 'All Devices';
    var cweVal = cweFilter ? cweFilter.value : 'All CWE Types';
    var searchVal = (searchInput ? searchInput.value : '').toLowerCase();

    var filtered = _results.filter(function (r) {
      if (devVal !== 'All Devices' && r.device !== devVal) return false;
      if (cweVal !== 'All CWE Types' && r.cwe !== cweVal) return false;
      if (searchVal) {
        var hay = (r.cwe + ' ' + r.sink + ' ' + r.source + ' ' + r.device + ' ' + r.firmware).toLowerCase();
        if (hay.indexOf(searchVal) === -1) return false;
      }
      return true;
    });

    _renderResults(filtered);
  }

  function _initFilters() {
    var devFilter = document.getElementById('results-device-filter');
    var cweFilter = document.getElementById('results-cwe-filter');
    var searchInput = document.getElementById('results-search');

    if (devFilter) devFilter.addEventListener('change', _applyFilters);
    if (cweFilter) cweFilter.addEventListener('change', _applyFilters);
    if (searchInput) searchInput.addEventListener('input', _applyFilters);
  }

  async function _loadLatestTask() {
    var container = document.getElementById('results-list');
    try {
      var resp = await api.get('/api/scan/tasks');
      var tasks = (resp.tasks || []).filter(function (t) { return t.status === 'done' && t.output_dir; });
      if (tasks.length > 0) {
        var latest = tasks[tasks.length - 1];
        window.__lastTaskId = latest.task_id;
        window.__lastOutputDir = latest.output_dir;
        loadResults(latest.task_id);
        return;
      }
    } catch (e) {
      console.error('Failed to discover tasks:', e);
    }
    if (container) {
      container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted);">' +
        'No completed scans found.<br><br>Run a scan in the <b>Analysis</b> tab first, then return here.' +
        '</div>';
    }
  }

  async function loadResults(taskId) {
    if (!taskId) return;

    var container = document.getElementById('results-list');
    if (container) container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted);">Loading results...</div>';

    try {
      var resp = await api.get('/api/results', { task_id: taskId });
      _results = resp.results || [];
      _outputDir = resp.output_dir || '';
      _taskId = resp.task_id || taskId;
      _firmwareName = (_results.length && _results[0].firmware) || '';

      // Expose for LLMReview
      window.__lastOutputDir = _outputDir;
      window.__lastTaskId = _taskId;

      _populateFilters(_results);
      _renderResults(_results);
    } catch (e) {
      if (container) container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--danger);">Failed to load results: ' + e.message + '</div>';
      console.error('loadResults error:', e);
    }
  }

  AppState.registerPage('results', {
    init: function () {
      if (!_initialized) {
        _initialized = true;
        _initFilters();

        // Bind save/delete buttons (once)
        var saveBtn = document.getElementById('btn-save-history');
        var delBtn = document.getElementById('btn-delete-selected');
        if (saveBtn) saveBtn.addEventListener('click', saveSelected);
        if (delBtn) delBtn.addEventListener('click', deleteSelected);

        // Detail button handler (stopPropagation to not toggle LLM selection)
        var list = document.getElementById('results-list');
        if (list) {
          list.addEventListener('click', function (e) {
            var detailBtn = e.target.closest('.result-detail-btn');
            if (detailBtn) {
              e.stopPropagation();
              _showResultDetail(detailBtn.dataset.resultId);
            }
          });
        }
      }

      var taskId = window.__lastTaskId;
      if (taskId && !_taskId) {
        loadResults(taskId);
      } else if (!taskId && !_taskId) {
        _loadLatestTask();
      }
      // else: keep existing results, don't re-render

      if (typeof LLMReview !== 'undefined') {
        LLMReview.init();
      }
    },
    destroy: function () {
      // Don't clear results — keep them for when user comes back
      if (typeof LLMReview !== 'undefined') {
        LLMReview.destroy();
      }
    },
  });

  // Expose for auto-save from analysis.js / app.js
  window.__resultsAutoSave = autoSaveRemaining;
  window.__resultsGetRemaining = getRemainingIds;

  window.addEventListener('beforeunload', function () {
    if (_results.length && _taskId) {
      // Best-effort sync save via sendBeacon
      var ids = _results.map(function (r) { return r.id; });
      var verdicts = (typeof LLMReview !== 'undefined' && LLMReview.getVerdicts)
        ? LLMReview.getVerdicts() : {};
      var payload = JSON.stringify({ task_id: _taskId, result_ids: ids, verdicts: verdicts });
      try { navigator.sendBeacon('/api/history', new Blob([payload], { type: 'application/json' })); } catch (e) {}
    }
  });

})();
