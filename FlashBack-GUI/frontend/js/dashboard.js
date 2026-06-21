/* ============================================================
   FlashBack GUI — dashboard.js
   仪表盘页逻辑 — 成员 C 实现

   功能：动态统计卡片 + 最近扫描 + 漏洞概览 + 快速操作
   数据：当前使用 mock 数据，待成员 B 的 results API 完成后切换
   ============================================================ */

var Dashboard = (function () {
  'use strict';

  var _uptimeInterval = null;
  var _totalScanSeconds = 0;

  // ── mock data ─────────────────────────────────────────

  function _mockStats() {
    return {
      scans: 12,
      vulns: 239,
      devices: 8,
    };
  }

  function _mockRecentScans() {
    return [
      { device: 'Tenda AX-1806',   firmware: 'tdhttpd',     time: '2 min ago',  vulns: 11, status: 'done' },
      { device: 'TOTOLINK A7000',  firmware: 'cgibin',      time: '15 min ago', vulns: 6,  status: 'done' },
      { device: 'Tenda AX-3',      firmware: 'httpd',       time: '1 hour ago', vulns: 10, status: 'done' },
      { device: 'Netgear RAX-30',  firmware: 'uhttpd',      time: '3 hours ago', vulns: 7,  status: 'done' },
      { device: 'TOTOLINK LR350',  firmware: 'httpd',       time: '5 hours ago', vulns: 7,  status: 'done' },
      { device: 'Tenda W15E',      firmware: 'cfg_server',  time: '6 hours ago', vulns: 5,  status: 'done' },
      { device: 'FortiGate SSLVPN',firmware: 'init',        time: '1 day ago',   vulns: 1,  status: 'done' },
      { device: 'TP-LINK XDR1850', firmware: 'httpd',       time: '2 days ago',  vulns: 4,  status: 'done' },
    ];
  }

  function _mockVulnOverview() {
    return [
      { cwe: 'CWE-78',  label: 'OS CMD INJ',  count: 89,  color: 'var(--danger)' },
      { cwe: 'CWE-120', label: 'BUF OVERFLOW', count: 64,  color: 'var(--warning)' },
      { cwe: 'CWE-134', label: 'FORMAT STR',   count: 31,  color: 'var(--accent-cyan)' },
      { cwe: 'CWE-22',  label: 'PATH TRAV',    count: 22,  color: 'var(--accent-purple)' },
      { cwe: 'CWE-89',  label: 'SQL INJ',      count: 15,  color: 'var(--accent)' },
      { cwe: 'Other',   label: 'OTHER',        count: 18,  color: 'var(--text-muted)' },
    ];
  }

  function _mockActivity() {
    return [
      { text: 'Scan completed — Tenda AX-1806 (tdhttpd)',        time: '2 min ago',  type: 'done' },
      { text: 'CVE-2025-70645 confirmed via Coordinated Disc.',   time: '20 min ago', type: 'info' },
      { text: 'LLM review completed — 11/11 verified',           time: '30 min ago', type: 'review' },
      { text: 'Scan completed — TOTOLINK A7000 (cgibin)',        time: '45 min ago', type: 'done' },
    ];
  }

  // ── render helpers ────────────────────────────────────

  function _setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function _renderRecentScans() {
    var container = document.getElementById('dash-recent-scans');
    if (!container) return;
    var scans = _mockRecentScans();
    container.innerHTML = scans.map(function (s, i) {
      var barColor = 'var(--success)';
      var statusText = s.vulns + ' vulns';
      return (
        '<a href="#results" class="dash-scan-row">' +
          '<div class="dash-scan-bar" style="background:' + barColor + ';"></div>' +
          '<div class="dash-scan-info">' +
            '<span class="dash-scan-name">' + _esc(s.device) + '</span>' +
            '<span class="dash-scan-meta">' + _esc(s.firmware) + '</span>' +
          '</div>' +
          '<div class="dash-scan-right">' +
            '<span class="dash-scan-vulns">' + statusText + '</span>' +
            '<span class="dash-scan-time">' + _esc(s.time) + '</span>' +
          '</div>' +
        '</a>'
      );
    }).join('');
  }

  function _renderVulnOverview() {
    var container = document.getElementById('dash-vuln-overview');
    if (!container) return;
    var items = _mockVulnOverview();
    var max = Math.max.apply(null, items.map(function (x) { return x.count; }));
    container.innerHTML = items.map(function (v) {
      var barW = Math.round((v.count / max) * 100);
      return (
        '<div class="dash-cwe-row">' +
          '<div class="dash-cwe-head">' +
            '<span class="code-label">' + _esc(v.cwe) + '</span>' +
            '<span class="dash-cwe-count">' + v.count + '</span>' +
          '</div>' +
          '<div class="dash-cwe-track">' +
            '<div class="dash-cwe-fill" style="width:' + barW + '%;background:' + v.color + ';"></div>' +
          '</div>' +
        '</div>'
      );
    }).join('');
  }

  function _renderActivity() {
    var container = document.getElementById('dash-activity-list');
    if (!container) return;
    var items = _mockActivity();
    var typeColors = { done: 'var(--success)', info: 'var(--accent)', review: 'var(--accent-cyan)' };
    container.innerHTML = items.map(function (a) {
      var dotColor = typeColors[a.type] || 'var(--text-muted)';
      return (
        '<div class="dash-activity-row">' +
          '<span class="dash-activity-dot" style="background:' + dotColor + ';"></span>' +
          '<div class="dash-activity-body">' +
            '<span class="dash-activity-text">' + _esc(a.text) + '</span>' +
            '<span class="dash-activity-time">' + _esc(a.time) + '</span>' +
          '</div>' +
        '</div>'
      );
    }).join('');
  }

  function _renderAll() {
    var stats = _mockStats();
    _setText('dash-scans',   stats.scans);
    _setText('dash-vulns',   stats.vulns);
    _setText('dash-devices', stats.devices);
    _renderRecentScans();
    _renderVulnOverview();
    _renderActivity();
  }

  function _formatDuration(totalSeconds) {
    var h = Math.floor(totalSeconds / 3600);
    var m = Math.floor((totalSeconds % 3600) / 60);
    var s = Math.floor(totalSeconds % 60);
    if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
    if (m > 0) return m + 'm ' + s + 's';
    return s + 's';
  }

  async function _refreshUptime() {
    try {
      var resp = await api.get('/api/scan/tasks');
      var tasks = resp.tasks || [];
      var hasRunning = tasks.some(function (t) { return t.status === 'running'; });

      // Sum elapsed time from all tasks (done + running)
      var total = 0;
      tasks.forEach(function (t) {
        total += (t.elapsed_seconds || 0);
      });

      _totalScanSeconds = total;
      _setText('dash-uptime', total > 0 ? _formatDuration(total) : '--');

      var trendEl = document.getElementById('dash-uptime-trend');
      if (trendEl) {
        if (hasRunning) {
          trendEl.textContent = 'live';
          trendEl.className = 'stat-card-trend up';
        } else {
          trendEl.textContent = 'idle';
          trendEl.className = 'stat-card-trend idle';
        }
      }
    } catch (e) {
      console.error('Failed to refresh uptime:', e);
    }
  }

  function _startUptime() {
    _refreshUptime();
    // Poll every 2s — frequent enough for live feel, cheap enough for API
    _uptimeInterval = setInterval(_refreshUptime, 2000);
  }

  // ── quick actions ─────────────────────────────────────

  function _wireQuickActions() {
    var actions = {
      'dash-btn-scan':     'analysis',
      'dash-btn-results':  'results',
      'dash-btn-settings': 'settings',
    };
    Object.keys(actions).forEach(function (btnId) {
      var el = document.getElementById(btnId);
      if (el) {
        el.addEventListener('click', function () {
          AppState.navigateTo(actions[btnId]);
        });
      }
    });
  }

  function _esc(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  // ── lifecycle ─────────────────────────────────────────

  function init() {
    _renderAll();
    _startUptime();
    _wireQuickActions();
  }

  function destroy() {
    if (_uptimeInterval) {
      clearInterval(_uptimeInterval);
      _uptimeInterval = null;
    }
  }

  return { init: init, destroy: destroy };
})();

AppState.registerPage('dashboard', {
  init: function () { Dashboard.init(); },
  destroy: function () { Dashboard.destroy(); },
});
