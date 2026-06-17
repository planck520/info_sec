/* ============================================================
   设置页逻辑 — 成员 C 实现
   IDA 配置 / LLM 提供商切换 / 通用偏好
   ============================================================ */

// ── LLM 提供商默认参数 ────────────────────────────────────
var LLM_PROVIDERS = {
  deepseek: { name: 'DeepSeek', tag: 'DEEPSEEK', url: 'https://api.deepseek.com',          model: 'deepseek-chat' },
  openai:   { name: 'OpenAI',   tag: 'OPENAI',   url: 'https://api.openai.com/v1',         model: 'gpt-4o' },
  groq:     { name: 'Groq',     tag: 'GROQ',     url: 'https://api.groq.com/openai/v1',    model: 'llama-3.3-70b-versatile' },
  ollama:   { name: 'Ollama',   tag: 'OLLAMA',   url: 'http://localhost:11434/v1',         model: 'llama3.2' },
  custom:   { name: 'Custom',   tag: 'CUSTOM',   url: '',                                   model: '' },
};

var settingsInitialized = false;

function setIDAStatus(found, message) {
  var tagEl = document.getElementById('ida-tag');
  var dotEl = document.getElementById('ida-dot');
  var statusEl = document.getElementById('ida-status');
  if (tagEl) tagEl.textContent = found ? 'FOUND' : 'NOT FOUND';
  if (tagEl) tagEl.style.color = found ? '#22c55e' : '#f59e0b';
  if (dotEl) dotEl.style.background = found ? '#22c55e' : '#f59e0b';
  if (statusEl) statusEl.textContent = message || (found ? '已检测到 IDA Pro' : '未检测到 IDA Pro');
}

async function loadSettings() {
  try {
    var data = await api.get('/api/settings');
    var idaEl = document.getElementById('settings-ida-path');
    var providerEl = document.getElementById('settings-llm-provider');
    var urlEl = document.getElementById('settings-llm-url');
    var modelEl = document.getElementById('settings-llm-model');
    var keyEl = document.getElementById('settings-llm-key');
    var llmToggle = document.getElementById('settings-llm-enabled');

    if (idaEl) idaEl.value = data.ida_path || '';
    if (providerEl) providerEl.value = data.llm_provider || 'deepseek';
    if (urlEl) urlEl.value = data.llm_base_url || '';
    if (modelEl) modelEl.value = data.llm_model || '';
    if (keyEl) keyEl.value = data.llm_api_key || '';
    if (llmToggle) llmToggle.classList.toggle('on', data.llm_enabled !== false);
    setIDAStatus(Boolean(data.ida_path), data.ida_path ? 'IDA 路径已配置：' + data.ida_path : '未检测到 IDA Pro');
  } catch (err) {
    setIDAStatus(false, '读取设置失败：' + err.message);
  }
}

async function saveSettings(patch) {
  try {
    await api.post('/api/settings', patch);
    if (patch.ida_path != null) setIDAStatus(Boolean(patch.ida_path), patch.ida_path ? 'IDA 路径已保存：' + patch.ida_path : '未检测到 IDA Pro');
    showToast('设置已保存', 'success');
  } catch (err) {
    showToast('保存设置失败：' + err.message, 'error', 5000);
  }
}

async function detectIDA() {
  try {
    var resp = await api.post('/api/settings/detect-ida', {});
    if (resp.found) {
      var idaEl = document.getElementById('settings-ida-path');
      if (idaEl) idaEl.value = resp.path || '';
      setIDAStatus(true, resp.message + '：' + (resp.path || ''));
      showToast('IDA 已检测到', 'success');
    } else {
      setIDAStatus(false, resp.message || '未找到 IDA');
      showToast(resp.message || '未找到 IDA', 'warn', 5000);
    }
  } catch (err) {
    showToast('检测 IDA 失败：' + err.message, 'error', 5000);
  }
}

async function browseIDAPath() {
  var idaEl = document.getElementById('settings-ida-path');
  try {
    if (window.electronAPI && typeof window.electronAPI.selectDirectory === 'function') {
      var path = await window.electronAPI.selectDirectory('选择 IDA 安装目录');
      if (path && idaEl) {
        idaEl.value = path;
        await saveSettings({ ida_path: path });
      }
      return;
    }
  } catch (err) {
    showToast('打开目录选择窗口失败：' + err.message, 'error', 5000);
  }

  var manual = window.prompt('请输入 IDA 安装目录或 ida.exe/idat.exe 完整路径：', idaEl ? idaEl.value : '');
  if (manual && idaEl) {
    idaEl.value = manual.trim();
    await saveSettings({ ida_path: idaEl.value });
  }
}

function collectSettingsPatch() {
  var idaEl = document.getElementById('settings-ida-path');
  var providerEl = document.getElementById('settings-llm-provider');
  var urlEl = document.getElementById('settings-llm-url');
  var modelEl = document.getElementById('settings-llm-model');
  var keyEl = document.getElementById('settings-llm-key');
  var llmToggle = document.getElementById('settings-llm-enabled');
  return {
    ida_path: idaEl ? idaEl.value.trim() : '',
    llm_enabled: llmToggle ? llmToggle.classList.contains('on') : true,
    llm_provider: providerEl ? providerEl.value : 'deepseek',
    llm_base_url: urlEl ? urlEl.value.trim() : '',
    llm_api_key: keyEl ? keyEl.value.trim() : '',
    llm_model: modelEl ? modelEl.value.trim() : '',
  };
}

function initLLMProviderSwitch() {
  var providerEl = document.getElementById('settings-llm-provider');
  var urlEl = document.getElementById('settings-llm-url');
  var modelEl = document.getElementById('settings-llm-model');
  var tagEl = document.getElementById('llm-provider-tag');

  if (!providerEl || !urlEl || !modelEl || !tagEl) return;

  providerEl.addEventListener('change', function () {
    var p = LLM_PROVIDERS[this.value];
    if (!p) return;

    urlEl.value = p.url;
    urlEl.placeholder = p.url || 'https://api.example.com/v1';
    modelEl.value = p.model;
    modelEl.placeholder = p.model || 'model-name';
    tagEl.textContent = p.tag;
    saveSettings(collectSettingsPatch());
  });
}

function bindSettingsEvents() {
  if (settingsInitialized) return;
  settingsInitialized = true;

  initLLMProviderSwitch();

  var idaEl = document.getElementById('settings-ida-path');
  var browseBtn = idaEl && idaEl.parentElement ? idaEl.parentElement.querySelector('button') : null;
  var llmToggle = document.getElementById('settings-llm-enabled');
  var inputs = [
    idaEl,
    document.getElementById('settings-llm-url'),
    document.getElementById('settings-llm-model'),
    document.getElementById('settings-llm-key'),
  ];

  if (browseBtn) browseBtn.addEventListener('click', browseIDAPath);
  if (idaEl) idaEl.addEventListener('blur', function () { saveSettings({ ida_path: idaEl.value.trim() }); });
  inputs.forEach(function (el) {
    if (!el || el === idaEl) return;
    el.addEventListener('blur', function () { saveSettings(collectSettingsPatch()); });
  });
  if (llmToggle) {
    llmToggle.addEventListener('click', function () {
      llmToggle.classList.toggle('on');
      saveSettings(collectSettingsPatch());
    });
  }
}

AppState.registerPage('settings', {
  init: function () {
    bindSettingsEvents();
    loadSettings().then(detectIDA);
  },
  destroy: function () {},
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function () {
    bindSettingsEvents();
    loadSettings().then(detectIDA);
  });
} else {
  bindSettingsEvents();
  loadSettings().then(detectIDA);
}
