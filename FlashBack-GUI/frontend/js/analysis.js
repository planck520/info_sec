/* 分析页逻辑 — 成员 A 实现 */

(function () {
  'use strict';

  const RING_TOTAL = 565.5;

  const state = {
    firmwareDir: '',
    outputDir: '',
    firmwares: [],
    taskId: null,
    ws: null,
    timer: null,
    startedAt: null,
    initialized: false,
    autoScroll: true,
    lastProgress: null,
    currentItemKey: null,
    currentItemStartedAt: null,
    lastCompleted: 0,
    logCount: 0,   // number of log lines already displayed from polling
  };

  function $(id) { return document.getElementById(id); }

  function setText(id, text) {
    const el = $(id);
    if (el) el.textContent = text;
  }

  function setProgress(pct, label) {
    const percent = Math.max(0, Math.min(100, Number(pct) || 0));
    const ring = $('ring-fill');
    if (ring) ring.style.strokeDashoffset = RING_TOTAL - (percent / 100) * RING_TOTAL;
    setText('ring-pct', percent + '%');
    if (label) setText('ring-status', label);
  }

  function statusLabel(s) {
    var u = (s || '').toUpperCase();
    if (u === 'DONE') return 'OK';
    if (u === 'ERROR') return 'ERR';
    if (u === 'STOPPED') return 'STOP';
    return 'RUN';
  }

  function addLog(level, message, timestamp) {
    const term = $('terminal-body');
    if (!term) return;
    const div = document.createElement('div');
    div.className = 'terminal-line';
    const cls = level === 'ERROR' ? 'err' : (level === 'WARN' || level === 'WARNING' ? 'warn' : 'info');
    const ts = timestamp || new Date().toLocaleTimeString('zh-CN', { hour12: false });
    div.innerHTML = '<span class="ts">[' + escapeHtml(ts) + ']</span> <span class="' + cls + '">●</span> ' + escapeHtml(message || '');
    term.appendChild(div);
    trimTerminalLines(term, 200);
    if (state.autoScroll) term.scrollTop = term.scrollHeight;
  }

  function trimTerminalLines(term, maxLines) {
    while (term.children.length > maxLines) {
      term.removeChild(term.firstElementChild);
    }
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"]/g, function (ch) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch];
    });
  }

  function ensureControls() {
    if ($('analysis-controls')) return;

    const leftCol = document.querySelector('#page-analysis > div:last-child > div:first-child');
    if (!leftCol) return;

    const panel = document.createElement('div');
    panel.className = 'panel analysis-config-panel';
    panel.id = 'analysis-controls';
    panel.innerHTML = [
      '<div class="section-hd"><span class="dot amber"></span> ANALYSIS CONFIG</div>',
      '<div class="panel-body analysis-form">',
      '  <label class="analysis-field"><span>输出目录</span><div class="analysis-input-row"><input class="input" id="analysis-output-input" placeholder="例如 D:\\flashback-output"><button class="btn btn-secondary btn-sm" id="btn-select-output-dir">选择</button></div></label>',
      '  <div class="analysis-grid">',
      '    <label class="analysis-field"><span>分析模式</span><select class="select" id="analysis-mode"><option value="standard">标准模式</option><option value="nocache">禁用缓存</option><option value="nopropagator">禁用传播器</option></select></label>',
      '    <label class="analysis-field"><span>并行数</span><input class="input" id="analysis-parallel" type="number" min="1" max="4" value="1"></label>',
      '  </div>',
      '  <div class="analysis-list-head"><span>固件列表</span><span id="analysis-selected-count">0 selected</span></div>',
      '  <div class="firmware-list scrollbar" id="firmware-list"><div class="firmware-empty">尚未扫描固件目录</div></div>',
      '</div>',
    ].join('');

    leftCol.appendChild(panel);

    const startBtn = $('btn-start-scan');
    if (startBtn) startBtn.removeAttribute('onclick');

    const startWrap = startBtn && startBtn.parentElement;
    if (startWrap && !$('btn-stop-scan')) {
      const stopBtn = document.createElement('button');
      stopBtn.className = 'btn btn-secondary btn-sm';
      stopBtn.id = 'btn-stop-scan';
      stopBtn.disabled = true;
      stopBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1"/></svg> STOP';
      startWrap.appendChild(stopBtn);
    }
  }

  function bindEvents() {
    const selectBtn = $('btn-select-dir');
    const selectFileBtn = $('btn-select-file');
    const outputBtn = $('btn-select-output-dir');
    const startBtn = $('btn-start-scan');
    const stopBtn = $('btn-stop-scan');
    const autoBtn = $('btn-log-autoscroll');
    const copyBtn = $('btn-log-copy');
    const clearBtn = $('btn-log-clear');

    if (selectBtn) selectBtn.onclick = chooseFirmwareDir;
    if (selectFileBtn) selectFileBtn.onclick = chooseFirmwareFile;
    if (outputBtn) outputBtn.onclick = chooseOutputDir;
    if (startBtn) startBtn.onclick = startScan;
    if (stopBtn) stopBtn.onclick = stopScan;
    if (autoBtn) autoBtn.onclick = toggleAutoScroll;
    if (copyBtn) copyBtn.onclick = copyLogs;
    if (clearBtn) clearBtn.onclick = clearLogs;
    updateAutoScrollButton();

    const list = $('firmware-list');
    if (list) {
      list.addEventListener('change', function (e) {
        if (e.target && e.target.matches('input[type="checkbox"]')) updateSelectedCount();
      });
    }
  }

  function updateAutoScrollButton() {
    const btn = $('btn-log-autoscroll');
    if (!btn) return;
    btn.classList.toggle('active', state.autoScroll);
    btn.textContent = state.autoScroll ? 'AUTO ON' : 'AUTO OFF';
  }

  function toggleAutoScroll() {
    state.autoScroll = !state.autoScroll;
    updateAutoScrollButton();
    if (state.autoScroll) {
      const term = $('terminal-body');
      if (term) term.scrollTop = term.scrollHeight;
    }
  }

  async function copyLogs() {
    const term = $('terminal-body');
    if (!term) return;
    const text = Array.from(term.querySelectorAll('.terminal-line')).map(function (line) {
      return line.textContent || '';
    }).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      showToast('日志已复制到剪贴板', 'success');
    } catch (err) {
      showToast('复制失败：' + err.message, 'error', 4000);
    }
  }

  function clearLogs() {
    const term = $('terminal-body');
    if (!term) return;
    term.innerHTML = '';
    addLog('INFO', '日志已清空');
  }

  async function selectDirectory(title) {
    if (window.electronAPI && typeof window.electronAPI.selectDirectory === 'function') {
      return window.electronAPI.selectDirectory(title);
    }
    const resp = await api.get('/api/scan/select-dir', { title: title || '选择目录' });
    return resp && resp.path;
  }

  async function selectFile(title) {
    if (window.electronAPI && typeof window.electronAPI.selectFile === 'function') {
      return window.electronAPI.selectFile(title);
    }
    const resp = await api.get('/api/scan/select-file', { title: title || '选择固件二进制文件' });
    return resp && resp.path;
  }

  async function chooseFirmwareDir() {
    let next = null;
    try {
      next = await selectDirectory('选择固件目录', state.firmwareDir);
    } catch (err) {
      showToast('打开目录选择窗口失败：' + err.message, 'error', 5000);
      next = window.prompt('请输入固件目录完整路径：', state.firmwareDir || '');
    }
    if (!next) return;
    await scanPath(String(next).trim());
  }

  async function chooseFirmwareFile() {
    let next = null;
    try {
      next = await selectFile('选择固件二进制文件');
    } catch (err) {
      showToast('打开文件选择窗口失败：' + err.message, 'error', 5000);
      next = window.prompt('请输入固件二进制文件完整路径：', '');
    }
    if (!next) return;
    await scanPath(String(next).trim());
  }

  async function chooseOutputDir() {
    const input = $('analysis-output-input');
    let next = null;
    try {
      next = await selectDirectory('选择输出目录', input ? input.value : '');
    } catch (err) {
      showToast('打开输出目录选择窗口失败：' + err.message, 'error', 5000);
      next = window.prompt('请输入输出目录完整路径：', input ? input.value : '');
    }
    if (next && input) input.value = String(next).trim();
  }

  async function scanPath(path) {
    state.firmwareDir = path;
    if (!state.firmwareDir) {
      showToast('请先选择固件目录或二进制文件', 'warn');
      return;
    }

    setEngineTag('SCANNING', '#f59e0b');
    setText('dir-path', state.firmwareDir);
    addLog('INFO', '扫描分析对象：' + state.firmwareDir);

    try {
      const data = await api.get('/api/scan/dir', { path: state.firmwareDir });
      state.firmwares = data.firmwares || [];
      renderFirmwareList();
      setEngineTag('READY', '#22c55e');
      setText('stat-status', 'READY');
      setText('stat-status-sub', '发现 ' + state.firmwares.length + ' 个候选对象');
      showToast('发现 ' + state.firmwares.length + ' 个候选对象', 'success');
      addLog('INFO', '对象扫描完成，发现 ' + state.firmwares.length + ' 个候选对象');
    } catch (err) {
      setEngineTag('ERROR', '#ef4444');
      showToast('对象扫描失败：' + err.message, 'error', 5000);
      addLog('ERROR', err.message);
    }
  }

  async function scanDirectory() {
    return scanPath(state.firmwareDir);
  }

  function renderFirmwareList() {
    const container = $('firmware-list');
    if (!container) return;
    if (!state.firmwares.length) {
      container.innerHTML = '<div class="firmware-empty">未发现可分析文件</div>';
      updateSelectedCount();
      return;
    }

    const groups = new Map();
    state.firmwares.forEach(function (fw) {
      if (!groups.has(fw.device)) groups.set(fw.device, []);
      groups.get(fw.device).push(fw);
    });

    container.innerHTML = Array.from(groups.entries()).map(function ([device, items]) {
      return '<div class="firmware-device">' +
        '<div class="firmware-device-name">📁 ' + escapeHtml(device) + ' <span>' + items.length + '</span></div>' +
        items.map(function (fw) {
          return '<label class="firmware-item">' +
            '<input type="checkbox" value="' + escapeHtml(fw.path) + '" checked>' +
            '<span class="firmware-name">' + escapeHtml(fw.name) + '</span>' +
            '<span class="firmware-meta">' + escapeHtml(fw.bits) + '-bit · ' + formatSize(fw.size) + '</span>' +
            '</label>';
        }).join('') +
        '</div>';
    }).join('');
    updateSelectedCount();
  }

  function updateSelectedCount() {
    const selected = getSelectedFirmwares();
    setText('analysis-selected-count', selected.length + ' selected');
  }

  function getSelectedFirmwares() {
    return Array.from(document.querySelectorAll('#firmware-list input[type="checkbox"]:checked')).map(function (el) {
      return el.value;
    });
  }

  function formatSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  async function startScan() {
    if (state.taskId) return;
    const selected = getSelectedFirmwares();
    const output = ($('analysis-output-input') && $('analysis-output-input').value.trim()) || '';
    const mode = ($('analysis-mode') && $('analysis-mode').value) || 'standard';
    const parallel = Number(($('analysis-parallel') && $('analysis-parallel').value) || 1);

    if (!selected.length) {
      showToast('请至少选择一个固件文件', 'warn');
      return;
    }
    if (!output) {
      showToast('请输入输出目录', 'warn');
      return;
    }

    resetRuntimeUi();
    state.lastProgress = null;
    state.currentItemKey = null;
    state.currentItemStartedAt = Date.now();
    state.lastCompleted = 0;
    state.logCount = 0;
    setRunning(true);
    addLog('INFO', '提交分析任务...');

    try {
      const resp = await api.post('/api/scan/start', {
        firmwares: selected,
        output_dir: output,
        mode: mode,
        parallel: parallel,
      });
      state.taskId = resp.task_id;
      state.outputDir = output;
      state.startedAt = Date.now();
      state.currentItemStartedAt = state.startedAt;
      connectLogs(state.taskId);
      addLog('INFO', '任务已创建：' + state.taskId);
    } catch (err) {
      setRunning(false);
      showToast('启动失败：' + err.message, 'error', 5000);
      addLog('ERROR', err.message);
    }
  }

  async function stopScan() {
    if (!state.taskId) return;
    try {
      await api.del('/api/scan/stop/' + encodeURIComponent(state.taskId));
      addLog('WARN', '已发送停止请求');
      setEngineTag('STOPPING', '#f59e0b');
    } catch (err) {
      showToast('停止失败：' + err.message, 'error', 5000);
      addLog('ERROR', err.message);
    }
  }

  function connectLogs(taskId) {
    if (state.ws) {
      state.ws.close();
      state.ws = null;
    }
    addLog('INFO', '开始监控分析进度...');
    _startPolling(taskId);
  }

  function _startPolling(taskId) {
    stopTimer();
    var lastLogIdx = state.logCount || 0;
    state.timer = setInterval(async function () {
      if (!state.taskId) return;

      // Update elapsed time (every tick for smooth display)
      if (state.startedAt) {
        var elapsed = Math.floor((Date.now() - state.startedAt) / 1000);
        var m = String(Math.floor(elapsed / 60)).padStart(2, '0');
        var s = String(elapsed % 60).padStart(2, '0');
        setText('stat-time', m + ':' + s);
      }

      try {
        var snap = await api.get('/api/scan/progress/' + encodeURIComponent(taskId));
        if (!snap) return;

        // Display new log lines
        if (snap.logs && snap.logs.length > lastLogIdx) {
          for (var i = lastLogIdx; i < snap.logs.length; i++) {
            var entry = snap.logs[i];
            addLog(entry.level || 'INFO', entry.message || '', entry.timestamp);
          }
          lastLogIdx = snap.logs.length;
          state.logCount = lastLogIdx;
        }

        handleProgress(snap);
        if (snap.status === 'done') {
          finishTask('DONE', snap);
        } else if (snap.status === 'error') {
          finishTask('ERROR', snap);
        } else if (snap.status === 'stopped') {
          finishTask('STOPPED', snap);
        }
      } catch (e) {
        // Retry next tick
      }
    }, 250);
  }

  function handleProgress(msg) {
    state.lastProgress = msg;
    const display = estimateDisplayProgress(msg);
    const label = msg.status === 'stopped' ? 'STOPPED' : (msg.current ? msg.current : 'RUNNING');
    setProgress(display, label);
    setEngineTag((msg.status || 'running').toUpperCase(), msg.status === 'error' ? '#ef4444' : '#f59e0b');
    setText('stat-status', statusLabel(msg.status || 'running'));
    setText('stat-status-sub', (msg.completed || 0) + '/' + (msg.total || 0) + ' · ~' + display + '%');
    setText('stat-vulns', String(msg.success || 0));
    setText('stat-vulns-sub', 'OK:' + (msg.success || 0) + '  FAIL:' + (msg.fail || 0));
  }

  function estimateDisplayProgress(msg) {
    const status = msg.status || 'running';
    const total = Math.max(0, Number(msg.total || 0));
    const completed = Math.max(0, Number(msg.completed || 0));
    const serverPct = Number(msg.progress != null ? msg.progress : (total ? Math.round(completed / total * 100) : 0));

    if (status === 'done') return 100;
    if (status === 'error' || status === 'stopped') return Math.max(0, Math.min(100, serverPct || 0));
    if (!total) return Math.max(1, Math.min(95, serverPct || 1));

    const itemKey = String(msg.current || '') + ':' + completed + '/' + total;
    if (state.currentItemKey !== itemKey || state.lastCompleted !== completed) {
      state.currentItemKey = itemKey;
      state.currentItemStartedAt = Date.now();
      state.lastCompleted = completed;
    }

    const base = Math.round((completed / total) * 100);
    const slot = Math.max(1, Math.round(100 / total));
    const elapsed = Math.max(0, Math.floor((Date.now() - (state.currentItemStartedAt || Date.now())) / 1000));
    const itemEstimate = estimateItemPercent(elapsed);
    const estimated = base + Math.round(slot * itemEstimate / 100);
    const cap = completed >= total ? 100 : Math.min(95, base + slot - 1);
    return Math.max(base, Math.min(cap, Math.max(serverPct || 0, estimated)));
  }

  function estimateItemPercent(elapsedSeconds) {
    if (elapsedSeconds <= 5) return 8 + elapsedSeconds * 2;
    if (elapsedSeconds <= 30) return 18 + (elapsedSeconds - 5) * 1.2;
    if (elapsedSeconds <= 120) return 48 + (elapsedSeconds - 30) * 0.35;
    if (elapsedSeconds <= 300) return 80 + (elapsedSeconds - 120) * 0.06;
    return 92;
  }

  function finishTask(label, msg) {
    const status = (msg.status || label || '').toUpperCase();
    const isOk = status === 'DONE';
    const isStopped = status === 'STOPPED';
    setProgress(isOk ? 100 : Number(msg.progress || 0), isOk ? 'COMPLETE' : status);
    setEngineTag(status, isOk ? '#22c55e' : (isStopped ? '#f59e0b' : '#ef4444'));
    setText('stat-status', statusLabel(msg.status || label || ''));
    setText('stat-status-sub', isOk ? '分析完成' : (msg.error || msg.message || '任务结束'));
    if (msg.message || msg.error) addLog(isOk ? 'INFO' : 'ERROR', msg.message || msg.error);
    if (msg.result_files && msg.result_files.length) addLog('INFO', '结果文件：' + msg.result_files.join(', '));
    showToast(isOk ? '分析完成' : ('任务结束：' + status), isOk ? 'success' : (isStopped ? 'warn' : 'error'));
    setRunning(false);
    // Expose for Results page and LLM review
    window.__lastTaskId = state.taskId;
    window.__lastOutputDir = state.outputDir;
    state.taskId = null;
  }

  function resetRuntimeUi() {
    const term = $('terminal-body');
    if (term) term.innerHTML = '';
    setProgress(0, '准备启动');
    setText('stat-vulns', '0');
    setText('stat-vulns-sub', '等待结果');
    setText('stat-time', '00:00');
  }

  function setRunning(running) {
    const startBtn = $('btn-start-scan');
    const stopBtn = $('btn-stop-scan');
    if (startBtn) {
      startBtn.disabled = running;
      startBtn.innerHTML = running
        ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> SCANNING...'
        : '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> START SCAN';
    }
    if (stopBtn) stopBtn.disabled = !running;
    const glow = $('ring-glow');
    if (glow) glow.classList.toggle('on', running);
    if (!running) stopTimer();
  }

  function setEngineTag(text, color) {
    const tag = $('scan-engine-tag');
    if (tag) {
      tag.textContent = text;
      if (color) tag.style.color = color;
    }
  }

  function startTimer() {
    stopTimer();
    state.timer = setInterval(function () {
      if (!state.startedAt) return;
      const elapsed = Math.floor((Date.now() - state.startedAt) / 1000);
      const m = String(Math.floor(elapsed / 60)).padStart(2, '0');
      const s = String(elapsed % 60).padStart(2, '0');
      setText('stat-time', m + ':' + s);
      if (state.lastProgress && state.lastProgress.status === 'running') {
        handleProgress(state.lastProgress);
      }
    }, 1000);
  }

  function stopTimer() {
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
  }

  function initAnalysisPage() {
    ensureControls();
    bindEvents();
    if (!state.initialized) {
      state.initialized = true;
      setProgress(0, '等待开始');
      setEngineTag('IDLE', '');
    }
    // Resume polling if we have a running task but timer was stopped by destroy
    if (state.taskId && !state.timer) {
      _startPolling(state.taskId);
    }
  }

  function destroyAnalysisPage() {
    stopTimer();
  }

  window.startScan = startScan;
  window.initAnalysisPage = initAnalysisPage;
  window.destroyAnalysisPage = destroyAnalysisPage;

  AppState.registerPage('analysis', {
    init: initAnalysisPage,
    destroy: destroyAnalysisPage,
  });
})();
