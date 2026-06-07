/* ============================================================
   FlashBack GUI — app.js
   SPA 路由控制器 + 全局状态管理

   使用方式（各页面模块）：
     AppState.registerPage('analysis', { init: initAnalysis, destroy: destroyAnalysis });
     AppState.navigateTo('results');
     AppState.getPageContainer();  → 当前页面的 DOM 容器
   ============================================================ */

const AppState = (() => {
  'use strict';

  let _currentPage = null;
  const _pages = {};
  const _state = {};

  // ── 注册页面生命周期 ──────────────────────────────────
  function registerPage(name, { init, destroy } = {}) {
    _pages[name] = {
      init: init || (() => {}),
      destroy: destroy || (() => {}),
    };
  }

  // ── 导航到指定页面 ────────────────────────────────────
  function navigateTo(pageName) {
    if (_currentPage === pageName) return;

    // 销毁旧页面
    if (_currentPage && _pages[_currentPage]) {
      try { _pages[_currentPage].destroy(); } catch (e) {
        console.error('[AppState] destroy error:', e);
      }
    }

    // 隐藏所有 section
    document.querySelectorAll('.page-section').forEach(
      s => s.classList.remove('active')
    );

    // 显示目标 section
    const target = document.getElementById('page-' + pageName);
    if (target) target.classList.add('active');

    // 导航高亮
    document.querySelectorAll('#sidebar-nav a').forEach(a => {
      a.classList.toggle('active', a.dataset.page === pageName);
    });

    // 初始化新页面
    _currentPage = pageName;
    if (_pages[pageName]) {
      try { _pages[pageName].init(); } catch (e) {
        console.error('[AppState] init error:', e);
      }
    }

    // 更新 hash（不触发重复 hashchange）
    if (location.hash !== '#' + pageName) {
      history.replaceState(null, '', '#' + pageName);
    }
  }

  // ── 获取当前页面容器 ──────────────────────────────────
  function getPageContainer(pageName) {
    return document.getElementById('page-' + (pageName || _currentPage));
  }

  // ── 全局状态读写 ──────────────────────────────────────
  function setState(k, v) { _state[k] = v; }
  function getState(k) { return _state[k]; }

  // ── 初始化 ────────────────────────────────────────────
  function init() {
    window.addEventListener('hashchange', () => {
      navigateTo(location.hash.replace('#', '') || 'dashboard');
    });

    document.getElementById('sidebar-nav').addEventListener('click', e => {
      const a = e.target.closest('a[data-page]');
      if (!a) return;
      e.preventDefault();
      navigateTo(a.dataset.page);
    });

    // 初始路由
    navigateTo(location.hash.replace('#', '') || 'dashboard');
  }

  return {
    init,
    registerPage,
    navigateTo,
    getPageContainer,
    getState,
    setState,
    get currentPage() { return _currentPage; },
  };
})();

document.addEventListener('DOMContentLoaded', () => AppState.init());
