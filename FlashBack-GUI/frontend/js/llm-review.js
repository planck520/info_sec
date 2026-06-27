/* ============================================================
   FlashBack GUI — llm-review.js
   LLM review: multi-select results → trigger review → poll status → show verdicts

   Integrated into the results page. Expects result cards to have
   class .result-card and attribute data-result-id.
   ============================================================ */

var LLMReview = (function () {
  'use strict';

  var _state = {
    reviewId: null,
    selectedIds: {},
    verdicts: {},
    pollingTimer: null,
    running: false,
  };

  // ── selection ─────────────────────────────────────────

  function toggleSelection(resultId) {
    if (_state.selectedIds[resultId]) {
      delete _state.selectedIds[resultId];
    } else {
      _state.selectedIds[resultId] = true;
    }
    _updateUI();
  }

  function selectAll() {
    var cards = document.querySelectorAll('.result-card[data-result-id]');
    cards.forEach(function (card) {
      _state.selectedIds[card.dataset.resultId] = true;
    });
    _updateUI();
  }

  function clearSelection() {
    _state.selectedIds = {};
    _updateUI();
  }

  function _selectedCount() {
    return Object.keys(_state.selectedIds).length;
  }

  function _updateUI() {
    var n = _selectedCount();

    var countEl = document.getElementById('llm-selected-count');
    if (countEl) countEl.textContent = n > 0 ? n + ' selected' : '';

    var btn = document.getElementById('llm-review-btn');
    if (btn) btn.disabled = n === 0 || _state.running;

    // Toggle card highlight
    document.querySelectorAll('.result-card[data-result-id]').forEach(function (card) {
      var id = card.dataset.resultId;
      if (_state.selectedIds[id]) {
        card.classList.add('selected');
      } else {
        card.classList.remove('selected');
      }
    });
  }

  // ── review lifecycle ──────────────────────────────────

  async function startReview() {
    var count = _selectedCount();
    if (count === 0) {
      showToast('Select at least one result', 'warning');
      return;
    }

    // Check LLM toggle — AppState (preloaded), fallback to API
    var llmEnabled = AppState.getState('llm_enabled');
    if (llmEnabled === undefined || llmEnabled === null) {
      try {
        var settings = await api.get('/api/settings');
        llmEnabled = settings.llm_enabled !== false;
        AppState.setState('llm_enabled', llmEnabled);
      } catch (e) { /* ignore, treat as disabled */ }
    }
    if (!llmEnabled) {
      showToast('LLM analysis is disabled. Enable it in Settings.', 'warning');
      return;
    }

    var modeEl = document.getElementById('llm-review-mode');
    var mode = modeEl ? modeEl.value : 'reasoning';
    var ids = Object.keys(_state.selectedIds);

    _state.running = true;
    _updateUI();

    try {
      // Hybrid: scan-set output_dir > settings-configured output_dir
      var outputDir = window.__lastOutputDir || AppState.getState('output_dir') || '';
      if (!outputDir) {
        showToast('No scan output directory found. Run a scan first.', 'error');
        _state.running = false;
        _updateUI();
        return;
      }
      var resp = await api.post('/api/llm-review', {
        result_ids: ids,
        mode: mode,
        output_dir: outputDir,
      });

      _state.reviewId = resp.review_id;
      _markSelected('running', 'Analyzing...');
      _showProgress(true);
      _startPolling();
      showToast('LLM review started (' + count + ' paths)', 'info');

    } catch (e) {
      _state.running = false;
      _updateUI();
      showToast('Failed to start review: ' + e.message, 'error');
    }
  }

  function _startPolling() {
    if (_state.pollingTimer) clearInterval(_state.pollingTimer);
    _state.pollingTimer = setInterval(_poll, 2000);
  }

  async function _poll() {
    if (!_state.reviewId) return;
    try {
      var resp = await api.get('/api/llm-review/' + _state.reviewId);

      _updateProgress(resp.progress);

      // Store model info for display on cards
      if (resp.model) {
        _state._modelInfo = resp.model + (resp.mode ? ' (' + resp.mode + ')' : '');
      }

      if (resp.results) {
        resp.results.forEach(function (r) {
          var card = document.querySelector(
            '.result-card[data-result-id="' + _escapeAttr(r.result_id) + '"]'
          );
          if (card && r.verdict) {
            _state.verdicts[r.result_id] = r.verdict;
            _renderVerdict(card, r.verdict);
          }
        });
      }

      if (resp.status === 'done') {
        _onDone();
      } else if (resp.status === 'error') {
        _onError(resp.error || 'Unknown error');
      }
    } catch (e) {
      console.error('LLM poll error:', e);
    }
  }

  function _onDone() {
    _stopPolling();
    _state.running = false;
    _showProgress(false);
    _updateUI();
    _resetButton();
    showToast('LLM review complete', 'success');
  }

  function _onError(msg) {
    _stopPolling();
    _state.running = false;
    _showProgress(false);
    _updateUI();
    _resetButton();
    showToast('LLM review failed: ' + msg, 'error');
  }

  function _stopPolling() {
    if (_state.pollingTimer) {
      clearInterval(_state.pollingTimer);
      _state.pollingTimer = null;
    }
  }

  // ── UI helpers ────────────────────────────────────────

  function _markSelected(status, text) {
    Object.keys(_state.selectedIds).forEach(function (id) {
      var card = document.querySelector('.result-card[data-result-id="' + _escapeAttr(id) + '"]');
      if (card) _setBadge(card, status, text);
    });
  }

  function _renderVerdict(card, verdict) {
    var reasoning = verdict.reasoning_chain || verdict.analysis_result || verdict.error || '';
    var hasError = _isErrorVerdict(verdict, reasoning);
    var isVuln = verdict.is_vulnerable;
    var badgeClass = hasError ? 'failed' : (isVuln ? 'vulnerable' : 'safe');
    var badgeText = hasError ? 'CONNECTION FAILED' : (isVuln ? 'VULNERABLE' : 'SAFE');
    _setBadge(card, hasError ? 'failed' : 'completed', badgeText, badgeClass);

    // Reasoning panel
    var panel = card.querySelector('.llm-reasoning');
    if (!panel) {
      panel = document.createElement('div');
      panel.className = 'llm-reasoning';
      card.appendChild(panel);
    }
    panel.classList.add('open');

    var conf = verdict.confidence != null
      ? ' (confidence: ' + (Math.round(verdict.confidence * 100)) + '%)'
      : '';
    var headerClass = hasError ? 'review-error' : (isVuln ? 'true-positive' : 'false-positive');
    var headerIcon = hasError ? 'LLM CONNECTION FAILED' : (isVuln ? 'TRUE POSITIVE' : 'FALSE POSITIVE / SAFE');
    var modelTag = _state._modelInfo || '';

    panel.innerHTML =
      '<div class="verdict-header ' + headerClass + '">' +
        headerIcon + conf +
        (modelTag ? '<span style="font-weight:400;font-size:10px;color:var(--text-muted);margin-left:8px;">' + _escapeHtml(modelTag) + '</span>' : '') +
      '</div>' +
      '<div class="verdict-reasoning">' + _escapeHtml(reasoning) + '</div>';
  }

  function _isErrorVerdict(verdict, reasoning) {
    if (!verdict) return true;
    if (verdict.error) return true;
    var text = (reasoning || '').toLowerCase();
    return text.indexOf('error:') !== -1 ||
      text.indexOf('http request failed') !== -1 ||
      text.indexOf('unauthorized') !== -1 ||
      text.indexOf('unable to connect') !== -1 ||
      text.indexOf('timed out') !== -1 ||
      text.indexOf('model returned empty response') !== -1;
  }

  function _setBadge(card, status, text, extraClass) {
    var badge = card.querySelector('.llm-badge');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'llm-badge';
      // Insert before the first child of the card's top area, or just prepend
      card.insertBefore(badge, card.firstChild);
    }
    badge.className = 'llm-badge ' + status + (extraClass ? ' ' + extraClass : '');
    if (status === 'running') {
      badge.innerHTML = '<span class="llm-spinner"></span> ' + _escapeHtml(text);
    } else {
      badge.textContent = text;
    }
  }

  function _updateProgress(progress) {
    if (!progress) return;
    var bar = document.getElementById('llm-review-progress-bar');
    var text = document.getElementById('llm-review-progress-text');
    if (bar && progress.total > 0) {
      var pct = (progress.completed / progress.total) * 100;
      bar.style.width = pct + '%';
    }
    if (text) {
      text.textContent = (progress.completed || 0) + ' / ' + (progress.total || 0);
    }
  }

  function _showProgress(visible) {
    var el = document.getElementById('llm-review-progress-wrap');
    if (el) el.style.display = visible ? 'flex' : 'none';
  }

  function _resetButton() {
    var btn = document.getElementById('llm-review-btn');
    if (btn) {
      btn.innerHTML = 'AI Review';
      btn.disabled = false;
    }
  }

  function _escapeAttr(s) {
    return s.replace(/"/g, '\\"');
  }

  function _escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ── public API ────────────────────────────────────────
  var _llmInitialized = false;

  function init() {
    if (_llmInitialized) {
      // Reapply selection visual state (selectedIds preserved across page switches)
      _updateUI();
      return;
    }
    _llmInitialized = true;

    var btn = document.getElementById('llm-review-btn');
    if (btn) btn.addEventListener('click', startReview);

    var list = document.getElementById('results-list');
    if (list) {
      list.addEventListener('click', function (e) {
        var card = e.target.closest('.result-card[data-result-id]');
        if (card) {
          toggleSelection(card.dataset.resultId);
        }
      });
    }
  }

  function destroy() {
    _stopPolling();
    // Preserve _state.selectedIds — selection survives page switches
    _state.reviewId = null;
    _state.running = false;
  }

  function getVerdicts() {
    return _state.verdicts;
  }

  // Reapply verdict badges + selection to DOM cards (called after _renderResults)
  function reapplyVerdicts() {
    document.querySelectorAll('.result-card[data-result-id]').forEach(function (card) {
      var id = card.dataset.resultId;
      if (_state.verdicts[id]) {
        _renderVerdict(card, _state.verdicts[id]);
      }
    });
  }

  return {
    init: init,
    destroy: destroy,
    toggleSelection: toggleSelection,
    selectAll: selectAll,
    clearSelection: clearSelection,
    getVerdicts: getVerdicts,
    reapplyVerdicts: reapplyVerdicts,
  };
})();
