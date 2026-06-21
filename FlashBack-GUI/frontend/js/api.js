/* ============================================================
   FlashBack GUI — api.js
   HTTP 请求封装 + WebSocket 连接工厂

   BASE_URL 自动从 window.location.origin 获取（🔴3 适配动态端口）
   ============================================================ */

const api = (() => {
  'use strict';

  const BASE_URL = window.location.origin;

  // ── 通用 fetch 包装 ───────────────────────────────────
  async function _request(method, path, paramsOrBody) {
    let url = BASE_URL + path;
    const options = { method, headers: {}, cache: 'no-store' };

    if (method === 'GET' || method === 'DELETE') {
      if (paramsOrBody) {
        url += '?' + new URLSearchParams(paramsOrBody).toString();
      }
    } else {
      options.headers['Content-Type'] = 'application/json';
      if (paramsOrBody) options.body = JSON.stringify(paramsOrBody);
    }

    const resp = await fetch(url, options);
    if (!resp.ok) {
      const text = await resp.text().catch(() => 'Unknown error');
      throw new Error('HTTP ' + resp.status + ': ' + text);
    }

    const cd = resp.headers.get('Content-Disposition');
    if (cd && cd.includes('attachment')) return resp.blob();
    return resp.json();
  }

  // ── WebSocket 连接工厂 ────────────────────────────────
  function connectWS(path, callbacks = {}) {
    const wsUrl = BASE_URL.replace('http', 'ws') + path;
    const { onLog, onProgress, onDone, onError, onOpen, onClose } = callbacks;

    let ws = null;
    let closed = false;
    let retries = 0;
    const maxRetries = 3;

    function connect() {
      if (closed) return;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        retries = 0;
        if (onOpen) onOpen();
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          switch (msg.type) {
            case 'log':      if (onLog) onLog(msg); break;
            case 'snapshot': if (onProgress) onProgress(msg); break;
            case 'progress': if (onProgress) onProgress(msg); break;
            case 'done':     if (onDone) onDone(msg); break;
            case 'stopped':  if (onDone) onDone(msg); break;
            case 'error':    if (onError) onError(msg); break;
          }
        } catch (e) {
          console.warn('[WS] parse error:', event.data);
        }
      };

      ws.onerror = () => { /* handled by onclose */ };

      ws.onclose = (e) => {
        if (closed) return;
        // 意外断开：指数退避重连
        if (retries < maxRetries && !e.wasClean) {
          const delay = Math.min(1000 * Math.pow(2, retries), 8000);
          retries++;
          console.warn('[WS] reconnect in ' + delay + 'ms (' + retries + '/' + maxRetries + ')');
          setTimeout(connect, delay);
        } else if (onClose) {
          onClose(e);
        }
      };
    }

    connect();

    return {
      close() {
        closed = true;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.close(1000, 'Client disconnect');
        }
      },
      get readyState() { return ws ? ws.readyState : WebSocket.CLOSED; },
    };
  }

  return {
    get:     (path, params) => _request('GET', path, params),
    post:    (path, body)   => _request('POST', path, body),
    put:     (path, body)   => _request('PUT', path, body),
    del:     (path, params) => _request('DELETE', path, params),
    connectWS,
  };
})();
