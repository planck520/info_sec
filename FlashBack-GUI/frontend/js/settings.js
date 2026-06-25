/* ============================================================
   设置页逻辑
   IDA 配置 / LLM 提供商切换 / 模型选择 / 通用偏好
   ============================================================ */

(function () {
  'use strict';

  // ── LLM 提供商数据（URL 和模型均经过验证）─────────────────
  var LLM_PROVIDERS = {
    deepseek: {
      name: 'DeepSeek', tag: 'DEEPSEEK',
      url: 'https://api.deepseek.com',
      models: [
        { id: 'deepseek-chat',       name: 'DeepSeek-V3 (deepseek-chat)' },
        { id: 'deepseek-reasoner',   name: 'DeepSeek-R1 (deepseek-reasoner)' },
        { id: 'deepseek-v4-flash',   name: 'DeepSeek-V4 Flash [1M]' },
        { id: 'deepseek-v4-pro',     name: 'DeepSeek-V4 Pro [1M]' }
      ]
    },
    openai: {
      name: 'OpenAI', tag: 'OPENAI',
      url: 'https://api.openai.com/v1',
      models: [
        { id: 'gpt-4o',      name: 'GPT-4o' },
        { id: 'gpt-4.1',     name: 'GPT-4.1' },
        { id: 'o4-mini',     name: 'o4-mini' },
        { id: 'gpt-4-turbo', name: 'GPT-4 Turbo' }
      ]
    },
    grok: {
      name: 'xAI Grok', tag: 'GROK',
      url: 'https://api.x.ai/v1',
      models: [
        { id: 'grok-2',        name: 'Grok-2' },
        { id: 'grok-2-vision', name: 'Grok-2 Vision' }
      ]
    },
    ollama: {
      name: 'Ollama', tag: 'OLLAMA',
      url: 'http://localhost:11434/v1',
      models: [
        { id: 'llama3.2', name: 'Llama 3.2 (本地)' },
        { id: 'qwen2.5',  name: 'Qwen 2.5 (本地)' }
      ]
    },
    custom: {
      name: 'Custom', tag: 'CUSTOM',
      url: '',
      models: [
        { id: '', name: '— 自行输入 —' }
      ]
    }
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

  // ── toggle helpers ─────────────────────────────────────────

  function _setToggle(id, on) {
    var el = document.getElementById(id);
    if (!el) return;
    if (on) {
      el.classList.add('on');
      el.setAttribute('aria-checked', 'true');
    } else {
      el.classList.remove('on');
      el.setAttribute('aria-checked', 'false');
    }
  }

  function _isToggleOn(id) {
    var el = document.getElementById(id);
    return el ? el.classList.contains('on') : false;
  }

  function initLLMToggle() {
    var toggle = document.getElementById('settings-llm-enabled');
    if (!toggle) return;
    toggle.addEventListener('click', function () {
      this.classList.toggle('on');
      var on = this.classList.contains('on');
      this.setAttribute('aria-checked', on ? 'true' : 'false');
      saveSettings(true);
    });
  }

  // ── provider / model switch ────────────────────────────────

  function _populateModelSelect(providerKey) {
    var p = LLM_PROVIDERS[providerKey];
    if (!p) return;
    // Custom provider: show input, hide select
    if (providerKey === 'custom') {
      var selWrap2 = document.getElementById('settings-model-select-wrap');
      var inpWrap2 = document.getElementById('settings-model-input-wrap');
      if (selWrap2) selWrap2.style.display = 'none';
      if (inpWrap2) inpWrap2.style.display = 'block';
      return;
    }
    // Normal provider: show select
    var selWrap = document.getElementById('settings-model-select-wrap');
    var inpWrap = document.getElementById('settings-model-input-wrap');
    if (selWrap) selWrap.style.display = 'block';
    if (inpWrap) inpWrap.style.display = 'none';
    var sel = document.getElementById('settings-llm-model');
    if (!sel) return;
    sel.innerHTML = p.models.map(function (m) {
      return '<option value="' + m.id + '">' + m.name + '</option>';
    }).join('');
  }

  function _getModelValue() {
    var provider = _settingsField('settings-llm-provider');
    if (provider === 'custom') {
      return _settingsField('settings-llm-model-custom');
    }
    return _settingsField('settings-llm-model');
  }

  function initLLMProviderSwitch() {
    var providerEl = document.getElementById('settings-llm-provider');
    var urlEl = document.getElementById('settings-llm-url');
    var tagEl = document.getElementById('llm-provider-tag');
    var modelEl = document.getElementById('settings-llm-model');

    if (!providerEl || !urlEl || !tagEl) return;

    providerEl.addEventListener('change', function () {
      var p = LLM_PROVIDERS[this.value];
      if (!p) return;

      urlEl.value = p.url;
      urlEl.placeholder = p.url || 'https://api.example.com/v1';
      tagEl.textContent = p.tag;
      _populateModelSelect(this.value);
      saveSettings(true);
    });

    // Save on model change too
    if (modelEl) {
      modelEl.addEventListener('change', function () { saveSettings(true); });
    }
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
      var provider = settings.llm_provider || 'deepseek';

      _setSettingsField('settings-llm-provider', provider);
      _populateModelSelect(provider);
      if (provider === 'custom') {
        _setSettingsField('settings-llm-model-custom', settings.llm_model);
      } else {
        _setSettingsField('settings-llm-model', settings.llm_model);
      }
      _setSettingsField('settings-llm-url', settings.llm_base_url);
      _setSettingsField('settings-llm-key', settings.llm_api_key);
      _setSettingsField('settings-ida-path', settings.ida_path);
      _setSettingsField('settings-output-dir', settings.output_dir);
      _setToggle('settings-llm-enabled', settings.llm_enabled !== false);

      var tagEl = document.getElementById('llm-provider-tag');
      if (tagEl) {
        var p = LLM_PROVIDERS[provider];
        if (p) tagEl.textContent = p.tag;
      }
      _updateIDAStatus();

      AppState.setState('llm_enabled', settings.llm_enabled !== false);
      AppState.setState('output_dir', settings.output_dir || '');
    } catch (e) {
      console.error('Failed to load settings:', e);
    }
  }

  async function saveSettings(silent) {
    var keyEl = document.getElementById('settings-llm-key');
    var payload = {
      llm_provider: _settingsField('settings-llm-provider'),
      llm_base_url: _settingsField('settings-llm-url'),
      llm_model:    _getModelValue(),
      ida_path:     _settingsField('settings-ida-path'),
      output_dir:   _settingsField('settings-output-dir'),
      llm_enabled:  _isToggleOn('settings-llm-enabled'),
    };
    // Only send api_key if user typed a new value (not the masked placeholder)
    if (keyEl && keyEl.value && keyEl.value.indexOf('****') === -1) {
      payload.llm_api_key = keyEl.value;
    }
    // Strip empties so we don't wipe existing values
    Object.keys(payload).forEach(function (k) {
      if (payload[k] === '' || payload[k] === undefined) delete payload[k];
    });

    AppState.setState('llm_enabled', _isToggleOn('settings-llm-enabled'));

    try {
      await api.post('/api/settings', payload);
      _updateIDAStatus();
      if (!silent) showToast('Settings saved', 'success');
    } catch (e) {
      showToast('Save failed: ' + e.message, 'error');
    }
  }

  // ── Settings-specific buttons ───────────────────────────────

  function initSettingsSaveButton() {
    var btn = document.getElementById('settings-save-btn');
    if (btn) btn.addEventListener('click', function () { saveSettings(false); });

    // auto-save on blur for text fields
    ['settings-llm-url', 'settings-llm-key', 'settings-ida-path', 'settings-output-dir'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.addEventListener('blur', function () { saveSettings(true); });
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
            saveSettings(true);
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
            saveSettings(true);
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

  // ── Output dir browse ──────────────────────────────────────

  function initOutputBrowse() {
    var btn = document.getElementById('settings-output-browse');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var input = document.createElement('input');
      input.type = 'file';
      input.webkitdirectory = true;
      input.directory = true;
      input.addEventListener('change', function () {
        if (this.files && this.files.length > 0) {
          var fullPath = this.files[0].path || this.files[0].name;
          if (fullPath.indexOf('\\') !== -1 || fullPath.indexOf('/') !== -1) {
            var sep = fullPath.indexOf('\\') !== -1 ? '\\' : '/';
            var parts = fullPath.split(sep);
            parts.pop();
            _setSettingsField('settings-output-dir', parts.join(sep));
            saveSettings(true);
          }
        }
      });
      input.click();
    });
  }

  // ── Test Connection ────────────────────────────────────────

  async function testLLMConnection() {
    var payload = {
      llm_base_url: _settingsField('settings-llm-url'),
      llm_api_key:  _settingsField('settings-llm-key'),
      llm_model:    _getModelValue(),
    };
    // If key field shows masked value, we need the real key from saved config
    var keyEl = document.getElementById('settings-llm-key');
    if (keyEl && keyEl.value.indexOf('****') !== -1) {
      // Key is masked — backend will fall back to stored config
      delete payload.llm_api_key;
    }
    try {
      var resp = await api.post('/api/settings/test-llm', payload);
      if (resp.ok) {
        showToast(resp.message, 'success');
      } else {
        showToast(resp.message, 'error');
      }
    } catch (e) {
      showToast('Test failed: ' + e.message, 'error');
    }
  }

  // ── page lifecycle ─────────────────────────────────────────
  var _settingsEventsBound = false;

  AppState.registerPage('settings', {
    init: function () {
      // Always reload to keep AppState in sync (e.g. llm_enabled)
      loadSettings();
      if (_settingsEventsBound) return;
      _settingsEventsBound = true;
      initLLMProviderSwitch();
      initLLMToggle();
      initSettingsSaveButton();
      initIDAPathButtons();
      initOutputBrowse();
      var testBtn = document.getElementById('settings-test-llm');
      if (testBtn) testBtn.addEventListener('click', testLLMConnection);
    },
    destroy: function () {},
  });

})();
