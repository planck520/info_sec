/* ============================================================
   设置页逻辑 — 成员 C 实现
   IDA 配置 / LLM 提供商切换 / 通用偏好
   ============================================================ */

(function () {
  'use strict';

  // ── LLM 提供商默认参数 ────────────────────────────────────
  var LLM_PROVIDERS = {
    deepseek: { name: 'DeepSeek', tag: 'DEEPSEEK', url: 'https://api.deepseek.com',           model: 'deepseek-chat' },
    openai:   { name: 'OpenAI',   tag: 'OPENAI',   url: 'https://api.openai.com/v1',          model: 'gpt-4o' },
    groq:     { name: 'Groq',     tag: 'GROQ',     url: 'https://api.groq.com/openai/v1',     model: 'llama-3.3-70b-versatile' },
    ollama:   { name: 'Ollama',   tag: 'OLLAMA',   url: 'http://localhost:11434/v1',          model: 'llama3.2' },
    custom:   { name: 'Custom',   tag: 'CUSTOM',   url: '',                                   model: '' },
  };

  // ── helpers ────────────────────────────────────────────────

  function _settingsField(id) {
    var el = document.getElementById(id);
    return el ? el.value : '';
  }

  function _setSettingsField(id, value) {
    var el = document.getElementById(id);
    if (el) el.value = value || '';
  }

  // ── IDA 状态指示器更新 ────────────────────────────────────

  function setIDAStatus(found, message) {
    // IDA PRO CONFIGURATION 面板内的状态元素
    var tagEl = document.getElementById('ida-tag');
    var dotEl = document.getElementById('ida-dot');
    var statusEl = document.getElementById('ida-status');
    if (tagEl) {
      tagEl.textContent = found ? 'FOUND' : 'NOT FOUND';
      tagEl.style.color = found ? '#22c55e' : '#f59e0b';
    }
    if (dotEl) {
      dotEl.style.background = found ? '#22c55e' : 'var(--text-muted)';
    }
    if (statusEl) {
      statusEl.textContent = message || (found ? '已检测到 IDA Pro' : '未检测到 IDA Pro');
    }
    // SYSTEM STATUS 侧边栏
    var sDotEl = document.getElementById('s-ida-dot');
    var sTagEl = document.getElementById('s-ida-tag');
    if (sDotEl) sDotEl.style.background = found ? '#22c55e' : 'var(--text-muted)';
    if (sTagEl) sTagEl.textContent = found ? 'FOUND' : 'NOT FOUND';
  }

  function _idaPathHasValue() {
    var val = _settingsField('settings-ida-path');
    return val && val.trim().length > 0;
  }

  function _updateIDAStatus() {
    setIDAStatus(_idaPathHasValue());
  }

  // ── load / save ────────────────────────────────────────────

  async function loadSettings() {
    try {
      var settings = await api.get('/api/settings');
      _setSettingsField('settings-llm-provider', settings.llm_provider);
      _setSettingsField('settings-llm-url',      settings.llm_base_url);
      _setSettingsField('settings-llm-model',    settings.llm_model);
      _setSettingsField('settings-llm-key',      settings.llm_api_key);
      _setSettingsField('settings-ida-path',     settings.ida_path);

      var tagEl = document.getElementById('llm-provider-tag');
      if (tagEl) {
        var p = LLM_PROVIDERS[settings.llm_provider];
        if (p) tagEl.textContent = p.tag;
      }
      _updateIDAStatus();
    } catch (e) {
      console.error('Failed to load settings:', e);
    }
  }

  async function saveSettings() {
    var keyEl = document.getElementById('settings-llm-key');
    var payload = {
      llm_provider: _settingsField('settings-llm-provider'),
      llm_base_url: _settingsField('settings-llm-url'),
      llm_model:    _settingsField('settings-llm-model'),
      ida_path:     _settingsField('settings-ida-path'),
    };
    // Only send api_key if user typed a new value (not the masked placeholder)
    if (keyEl && keyEl.value && keyEl.value.indexOf('****') === -1) {
      payload.llm_api_key = keyEl.value;
    }
    // Strip empties so we don't wipe existing values
    Object.keys(payload).forEach(function (k) {
      if (payload[k] === '' || payload[k] === undefined) delete payload[k];
    });

    try {
      await api.post('/api/settings', payload);
      _updateIDAStatus();
      showToast('Settings saved', 'success');
    } catch (e) {
      showToast('Save failed: ' + e.message, 'error');
    }
  }

  // ── provider switch ────────────────────────────────────────

  function initLLMProviderSwitch() {
    var providerEl = document.getElementById('settings-llm-provider');
    var urlEl = document.getElementById('settings-llm-url');
    var modelEl = document.getElementById('settings-llm-model');
    var tagEl = document.getElementById('llm-provider-tag');

    if (!providerEl || !urlEl || !modelEl || !tagEl) return;

    providerEl.addEventListener('change', function () {
      var p = LLM_PROVIDERS[this.value];
      if (!p) return;

      urlEl.value   = p.url;
      urlEl.placeholder = p.url || 'https://api.example.com/v1';
      modelEl.value = p.model;
      modelEl.placeholder = p.model || 'model-name';
      tagEl.textContent = p.tag;

      // auto-save on provider switch
      saveSettings();
    });
  }

  function initSettingsSaveButton() {
    var btn = document.getElementById('settings-save-btn');
    if (btn) btn.addEventListener('click', saveSettings);

    // auto-save on blur for text fields
    ['settings-llm-url', 'settings-llm-model', 'settings-llm-key', 'settings-ida-path'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.addEventListener('blur', saveSettings);
    });
  }

  // ── IDA path buttons ───────────────────────────────────────

  function initIDAPathButtons() {
    var browseBtn = document.getElementById('btn-ida-browse');
    var detectBtn = document.getElementById('btn-ida-detect');
    var pathInput = document.getElementById('settings-ida-path');

    // Browse: prefer Electron native dialog, fallback to backend API
    if (browseBtn) {
      browseBtn.addEventListener('click', async function () {
        browseBtn.disabled = true;
        browseBtn.textContent = '…';
        try {
          var path = null;
          if (window.electronAPI && typeof window.electronAPI.selectFile === 'function') {
            path = await window.electronAPI.selectFile('选择 IDA 可执行文件 (ida.exe / idat64.exe)');
          } else {
            var resp = await api.get('/api/scan/select-file', { title: '选择 IDA 可执行文件' });
            path = resp && resp.path;
          }
          if (path) {
            pathInput.value = path;
            saveSettings();
          }
        } catch (e) {
          showToast('Select failed: ' + e.message, 'error');
        } finally {
          browseBtn.disabled = false;
          browseBtn.textContent = 'Browse';
        }
      });
    }

    // Auto Detect: call backend to find IDA, update status
    if (detectBtn) {
      detectBtn.addEventListener('click', async function () {
        detectBtn.disabled = true;
        detectBtn.textContent = 'Detecting…';
        try {
          var resp = await api.post('/api/settings/detect-ida', {});
          if (resp && resp.found) {
            pathInput.value = resp.path;
            setIDAStatus(true, resp.message || 'IDA 已检测到');
            saveSettings();
            showToast('IDA found: ' + resp.path, 'success');
          } else {
            setIDAStatus(false, resp.message || 'IDA not found');
            showToast(resp.message || 'IDA not found', 'warning');
          }
        } catch (e) {
          showToast('Detection failed: ' + e.message, 'error');
        } finally {
          detectBtn.disabled = false;
          detectBtn.textContent = 'Auto Detect';
        }
      });
    }
  }

  // ── page lifecycle ─────────────────────────────────────────

  AppState.registerPage('settings', {
    init: function () {
      initLLMProviderSwitch();
      initSettingsSaveButton();
      initIDAPathButtons();
      loadSettings();
    },
    destroy: function () {},
  });

})();
