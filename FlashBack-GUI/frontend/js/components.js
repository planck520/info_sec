/* ============================================================
   FlashBack GUI — components.js
   可复用 JS UI 组件

   showToast(message, type, duration) → void
   ============================================================ */

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
