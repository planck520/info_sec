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
  });
}

AppState.registerPage('settings', {
  init: function () {
    initLLMProviderSwitch();
  },
  destroy: function () {
    // TODO: 成员 C — 清理事件监听
  },
});
