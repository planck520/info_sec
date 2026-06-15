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

  function addLog(level, message, timestamp) {
    const term = $('terminal-body');
    if (!term) return;
    const div = document.createElement('div');
    div.className = 'terminal-line';
    const cls = level === 'ERROR' ? 'err' : (level === 'WARN' || level === 'WARNING' ? 'warn' : 'info');
    const ts = timestamp || new Date().toLocaleTimeString('zh-CN', { hour12: false });
    div.innerHTML = '<span class="ts">[' + escapeHtml(ts) + ']</span> <span class="' + cls + '">●</span> ' + escapeHtml(message || '');
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
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
      '  <label class="analysis-field"><span>固件目录</span><div class="analysis-input-row"><input class="input" id="analysis-dir-input" placeholder="例如 D:\\firmware"><button class="btn btn-secondary btn-sm" id="analysis-scan-dir">扫描</button></div></label>',
      '  <label class="analysis-field"><span>输出目录</span><input class="input" id="analysis-output-input" placeholder="例如 D:\\flashback-output"></label>',
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
      stopBtn.className = 'btn btn-secondary';
      stopBtn.id = 'btn-stop-scan';
      stopBtn.disabled = true;
      stopBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1"/></svg> STOP';
      startWrap.appendChild(stopBtn);
    }
  }

  function bindEvents() {
    const selectBtn = $('btn-select-dir');
    const scanBtn = $('analysis-scan-dir');
    const startBtn = $('btn-start-scan');
    const stopBtn = $('btn-stop-scan');

    if (selectBtn) selectBtn.onclick = chooseFirmwareDir;
    if (scanBtn) scanBtn.onclick = scanDirectory;
    if (startBtn) startBtn.onclick = startScan;
    if (stopBtn) stopBtn.onclick = stopScan;

    const list = $('firmware-list');
    if (list) {
      list.addEventListener('change', function (e) {
        if (e.target && e.target.matches('input[type="checkbox"]')) updateSelectedCount();
      });
    }
  }

  function chooseFirmwareDir() {
    const input = $('analysis-dir-input');
    const current = input ? input.value : state.firmwareDir;
    const next = window.prompt('请输入固件目录完整路径：', current || '');
    if (next == null) return;
    state.firmwareDir = next.trim();
    if (input) input.value = state.firmwareDir;
    setText('dir-path', state.firmwareDir || '<not selected>');
    if (state.firmwareDir) scanDirectory();
  }

  async function scanDirectory() {
    const input = $('analysis-dir-input');
    state.firmwareDir = (input && input.value.trim()) || state.firmwareDir;
    if (!state.firmwareDir) {
      showToast('请先输入固件目录', 'warn');
      return;
    }

    setEngineTag('SCANNING', '#f59e0b');
    setText('dir-path', state.firmwareDir);
    addLog('INFO', '扫描固件目录：' + state.firmwareDir);

    try {
      const data = await api.get('/api/scan/dir', { path: state.firmwareDir });
      state.firmwares = data.firmwares || [];
      renderFirmwareList();
      setEngineTag('READY', '#22c55e');
      setText('stat-status', 'READY');
      setText('stat-status-sub', '发现 ' + state.firmwares.length + ' 个固件');
      showToast('发现 ' + state.firmwares.length + ' 个固件文件', 'success');
      addLog('INFO', '目录扫描完成，发现 ' + state.firmwares.length + ' 个候选文件');
    } catch (err) {
      setEngineTag('ERROR', '#ef4444');
      showToast('目录扫描失败：' + err.message, 'error', 5000);
      addLog('ERROR', err.message);
    }
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
      startTimer();
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
    if (state.ws) state.ws.close();
    state.ws = api.connectWS('/ws/logs?task_id=' + encodeURIComponent(taskId), {
      onOpen: function () { addLog('INFO', '实时日志连接已建立'); },
      onLog: function (msg) { addLog(msg.level || 'INFO', msg.message || '', msg.timestamp); },
      onProgress: handleProgress,
      onDone: function (msg) { finishTask('DONE', msg); },
      onError: function (msg) { finishTask('ERROR', msg); },
      onClose: function () { addLog('WARN', '实时日志连接已断开'); },
    });
  }

  function handleProgress(msg) {
    const pct = Number(msg.progress != null ? msg.progress : (msg.total ? Math.round(msg.completed / msg.total * 100) : 0));
    const label = msg.status === 'stopped' ? 'STOPPED' : (msg.current ? msg.current : 'RUNNING');
    setProgress(pct, label);
    setEngineTag((msg.status || 'running').toUpperCase(), msg.status === 'error' ? '#ef4444' : '#f59e0b');
    setText('stat-status', (msg.status || 'RUN').toUpperCase().slice(0, 6));
    setText('stat-status-sub', (msg.completed || 0) + '/' + (msg.total || 0) + ' 已完成');
    setText('stat-vulns', String(msg.success || 0));
    setText('stat-vulns-sub', '成功 ' + (msg.success || 0) + ' / 失败 ' + (msg.fail || 0));
  }

  function finishTask(label, msg) {
    const status = (msg.status || label || '').toUpperCase();
    const isOk = status === 'DONE';
    const isStopped = status === 'STOPPED';
    setProgress(isOk ? 100 : Number(msg.progress || 0), isOk ? 'COMPLETE' : status);
    setEngineTag(status, isOk ? '#22c55e' : (isStopped ? '#f59e0b' : '#ef4444'));
    setText('stat-status', isOk ? 'OK' : status.slice(0, 6));
    setText('stat-status-sub', isOk ? '分析完成' : (msg.error || msg.message || '任务结束'));
    if (msg.message || msg.error) addLog(isOk ? 'INFO' : 'ERROR', msg.message || msg.error);
    if (msg.result_files && msg.result_files.length) addLog('INFO', '结果文件：' + msg.result_files.join(', '));
    showToast(isOk ? '分析完成' : ('任务结束：' + status), isOk ? 'success' : (isStopped ? 'warn' : 'error'));
    setRunning(false);
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
  }

  function destroyAnalysisPage() {
    if (state.ws) {
      state.ws.close();
      state.ws = null;
    }
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
