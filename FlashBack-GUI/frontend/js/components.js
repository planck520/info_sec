/* ============================================================
   FlashBack GUI — components.js
   可复用 JS UI 组件

   createProgressBar(container, { total })       → { update, complete, error }
   createLogViewer(container)                    → { addLog, clear }
   createResultTable(container, columns)         → { setData, onRowClick, clear, getSelected }
   createTerminal(container, { title })          → { addLine, clear }
   createCircularProgress(container, { radius }) → { update, complete }
   showToast(message, type, duration)            → void
   ============================================================ */

// ── 进度条 ──────────────────────────────────────────────────
function createProgressBar(container, { total = 1 } = {}) {
  const el = document.createElement('div');
  el.className = 'progress-container';
  el.innerHTML =
    '<div class="progress-bar"><div class="progress-bar-fill"></div></div>' +
    '<div class="progress-label"><span></span><span class="progress-current"></span></div>';
  container.appendChild(el);

  const fill = el.querySelector('.progress-bar-fill');
  const left = el.querySelector('.progress-label span');
  const right = el.querySelector('.progress-current');
  let completed = 0;

  function render() {
    const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
    fill.style.width = pct + '%';
    left.textContent = pct + '%';
    right.textContent = '(' + completed + '/' + total + ')';
  }
  render();

  return {
    update(c, label) {
      completed = c;
      render();
      if (label) right.textContent = label;
    },
    complete() {
      completed = total;
      render();
      fill.style.background = 'var(--success)';
    },
    error(msg) {
      fill.style.background = 'var(--danger)';
      left.textContent = msg || 'Error';
    },
  };
}

// ── 日志查看器 ──────────────────────────────────────────────
function createLogViewer(container) {
  const el = document.createElement('div');
  el.className = 'log-viewer';
  container.appendChild(el);

  return {
    addLog(level, msg, ts) {
      const line = document.createElement('div');
      line.className = 'log-line ' + level;
      const t = ts || new Date().toLocaleTimeString('zh-CN', { hour12: false });
      line.innerHTML = '<span class="timestamp">[' + t + ']</span> ' + _esc(msg);
      el.appendChild(line);
      el.scrollTop = el.scrollHeight;
    },
    clear() { el.innerHTML = ''; },
  };

  function _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
}

// ── 结果表格 ────────────────────────────────────────────────
// columns 使用 API 原始字段名: ['vuln_type', 'sink_func', 'source_func', 'device']
function createResultTable(container, columns = []) {
  const wrapper = document.createElement('div');
  wrapper.style.overflowX = 'auto';

  const table = document.createElement('table');
  table.className = 'data-table';

  const thead = document.createElement('thead');
  const hr = document.createElement('tr');
  columns.forEach(c => {
    const th = document.createElement('th');
    th.textContent = c;
    hr.appendChild(th);
  });
  thead.appendChild(hr);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  table.appendChild(tbody);
  wrapper.appendChild(table);
  container.appendChild(wrapper);

  let _data = [];
  let _selected = -1;
  let _onClick = null;

  tbody.addEventListener('click', e => {
    const tr = e.target.closest('tr');
    if (!tr || tr.dataset.index === undefined) return;
    const idx = parseInt(tr.dataset.index, 10);
    if (_selected === idx) {
      tr.classList.remove('selected');
      _selected = -1;
    } else {
      tbody.querySelectorAll('tr.selected').forEach(r => r.classList.remove('selected'));
      tr.classList.add('selected');
      _selected = idx;
    }
    if (_onClick && _selected >= 0) _onClick(_selected, _data[_selected]);
  });

  return {
    setData(rows) {
      _data = rows;
      _selected = -1;
      tbody.innerHTML = '';
      rows.forEach((row, i) => {
        const tr = document.createElement('tr');
        tr.dataset.index = i;
        columns.forEach(col => {
          const td = document.createElement('td');
          const v = row[col];
          td.textContent = v !== undefined && v !== null ? v : '';
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    },
    onRowClick(fn) { _onClick = fn; },
    clear() { _data = []; _selected = -1; tbody.innerHTML = ''; },
    getSelected() { return _selected >= 0 ? _data[_selected] : null; },
  };
}

// ── Toast 提示 ──────────────────────────────────────────────
function showToast(message, type, duration) {
  type = type || 'info';
  duration = duration || 3000;

  var container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  var el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = message;
  container.appendChild(el);

  setTimeout(function () {
    el.style.opacity = '0';
    el.style.transition = 'all 0.25s ease-out';
    el.style.transform = 'translateY(10px)';
    setTimeout(function () { el.remove(); }, 250);
  }, duration);
}

// ── 苹果风终端 ──────────────────────────────────────────────
function createTerminal(container, options) {
  options = options || {};
  var title = options.title || 'System Console';

  var wrapper = document.createElement('div');
  wrapper.className = 'terminal';

  var bar = document.createElement('div');
  bar.className = 'terminal-bar';
  bar.innerHTML =
    '<span class="terminal-dot red"></span>' +
    '<span class="terminal-dot amber"></span>' +
    '<span class="terminal-dot green"></span>' +
    '<span class="terminal-title">' + _escT(title) + '</span>';

  var body = document.createElement('div');
  body.className = 'terminal-body';

  wrapper.appendChild(bar);
  wrapper.appendChild(body);
  container.appendChild(wrapper);

  return {
    addLine: function (level, msg, ts) {
      var div = document.createElement('div');
      div.className = 'terminal-line';
      var t = ts || new Date().toLocaleTimeString('zh-CN', { hour12: false });
      var lvl = level || 'dim';
      div.innerHTML =
        '<span class="ts">[' + t + ']</span> ' +
        '<span class="' + lvl + '">' + lvl.toUpperCase() + '</span>  ' +
        _escT(msg);
      body.appendChild(div);
      body.scrollTop = body.scrollHeight;
    },
    clear: function () { body.innerHTML = ''; },
  };

  function _escT(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
}

// ── SVG 进度环 ──────────────────────────────────────────────
function createCircularProgress(container, options) {
  options = options || {};
  var size = options.size || 200;
  var radius = options.radius || 90;
  var strokeW = options.strokeWidth || 9;
  var cx = size / 2;
  var cy = size / 2;
  var circumference = 2 * Math.PI * radius;

  var wrapper = document.createElement('div');
  wrapper.className = 'progress-ring-container';
  wrapper.style.width = size + 'px';
  wrapper.style.height = size + 'px';

  wrapper.innerHTML =
    '<svg class="progress-ring" width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '">' +
      '<defs>' +
        '<linearGradient id="ringGradient_dyn" x1="0%" y1="0%" x2="100%" y2="100%">' +
          '<stop offset="0%" stop-color="#2563eb"/>' +
          '<stop offset="100%" stop-color="#0891b2"/>' +
        '</linearGradient>' +
      '</defs>' +
      '<circle class="progress-ring-bg" cx="' + cx + '" cy="' + cy + '" r="' + radius + '" stroke-width="' + strokeW + '"/>' +
      '<circle class="progress-ring-fill" cx="' + cx + '" cy="' + cy + '" r="' + radius + '" ' +
              'stroke-width="' + (strokeW + 1) + '" stroke="url(#ringGradient_dyn)" ' +
              'stroke-dasharray="' + circumference + '" stroke-dashoffset="' + circumference + '"/>' +
    '</svg>' +
    '<div class="progress-center">' +
      '<span class="progress-pct">0%</span>' +
      '<span class="progress-label">等待开始</span>' +
    '</div>' +
    '<div class="progress-ring-glow"></div>';

  container.appendChild(wrapper);

  var fill = wrapper.querySelector('.progress-ring-fill');
  var pctEl = wrapper.querySelector('.progress-pct');
  var labelEl = wrapper.querySelector('.progress-label');
  var glow = wrapper.querySelector('.progress-ring-glow');

  return {
    update: function (pct, label) {
      pct = Math.min(100, Math.max(0, pct));
      var offset = circumference - (pct / 100) * circumference;
      fill.style.strokeDashoffset = offset;
      pctEl.textContent = Math.round(pct) + '%';
      if (label) labelEl.textContent = label;
    },
    complete: function () {
      fill.style.strokeDashoffset = 0;
      pctEl.textContent = '100%';
      labelEl.textContent = '分析完成';
      fill.style.stroke = 'var(--success)';
      glow.classList.remove('active');
    },
    startGlow: function () {
      glow.classList.add('active');
    },
    stopGlow: function () {
      glow.classList.remove('active');
    },
  };
}
