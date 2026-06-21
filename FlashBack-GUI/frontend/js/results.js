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
        '<div class="result-card ' + r.sev + '" data-result-id="' + r.id + '" style="cursor:pointer;">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
            '<div class="flex-col gap-xs">' +
              '<div class="flex-row gap-sm" style="align-items:center;">' +
                '<span class="code-label" style="font-size:10px;">' + r.device + '</span>' +
                '<span class="text-xs text-muted">' + r.firmware + '</span>' +
                '<span class="text-xs text-muted">· ' + r.path_length + ' hops</span>' +
              '</div>' +
              '<span class="code-value" style="font-size:14px;">' + r.cwe + ' — ' + r.sink + '()</span>' +
              '<span class="text-xs text-muted">source: ' + r.source + '()  ·  path #' + r.id.split('/')[2] + '</span>' +
            '</div>' +
            '<span class="severity-badge" style="font-size:10px;padding:3px 8px;border-radius:4px;font-weight:600;' + sevStyle + '">' +
              r.sev.toUpperCase() +
            '</span>' +
          '</div>' +
        '</div>'
      );
    }).join('');
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
      _initFilters();

      var taskId = window.__lastTaskId;
      if (taskId) {
        loadResults(taskId);
      } else {
        // Auto-discover: find the most recent completed task
        _loadLatestTask();
      }

      if (typeof LLMReview !== 'undefined') {
        LLMReview.init();
      }
    },
    destroy: function () {
      if (typeof LLMReview !== 'undefined') {
        LLMReview.destroy();
      }
    },
  });

})();
