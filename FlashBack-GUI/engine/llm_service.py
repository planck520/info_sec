# coding: utf-8
"""LLM analyzer service adapter.

Wraps the standalone VulnerabilityAnalyzer (Reasoning-Guided) and
VulnerabilityAnalyzerWeakPrompt (Direct) classes so they can be called
with in-memory code content instead of disk file paths.

Handles provider-specific API differences:
- DeepSeek: supports ``thinking`` in extra_body
- OpenAI / Groq / Ollama: strips DeepSeek-specific extra_body
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

_RESOURCE_LLM = (
    Path(__file__).resolve().parent.parent / "resources" / "llm"
)
if str(_RESOURCE_LLM) not in sys.path:
    sys.path.insert(0, str(_RESOURCE_LLM))

from LLM_Direct_Prompt import VulnerabilityAnalyzerWeakPrompt  # noqa: E402
from LLM_Reasoning_Guided import VulnerabilityAnalyzer  # noqa: E402


def _is_deepseek(base_url: str) -> bool:
    return "deepseek" in base_url.lower()


def _code_hash(code_content: str, vuln_info: dict[str, Any]) -> str:
    raw = code_content + json.dumps(vuln_info, sort_keys=True, default=str)
    return hashlib.md5(raw.encode()).hexdigest()


def _patch_for_provider(analyzer, base_url: str) -> None:
    """Monkey-patch call_deepseek_model to strip DeepSeek-only ``extra_body``
    when the provider is NOT DeepSeek."""
    if _is_deepseek(base_url):
        return  # DeepSeek — keep extra_body.thinking intact

    original = analyzer.call_deepseek_model

    def patched_call(prompt: str, json_mode: bool = False) -> str:
        # Call the original but intercept the HTTP request to strip extra_body
        # We wrap the requests.post call by replacing it temporarily
        import requests as _requests
        _original_post = _requests.post

        def _patched_post(url, **kwargs):
            if "json" in kwargs and "extra_body" in kwargs["json"]:
                del kwargs["json"]["extra_body"]
            return _original_post(url, **kwargs)

        _requests.post = _patched_post
        try:
            return original(prompt, json_mode)
        finally:
            _requests.post = _original_post

    analyzer.call_deepseek_model = patched_call


class LLMReviewService:
    """Thin wrapper that initializes analyzers from settings values."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        output_dir: str,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._model = model
        # model-specific cache dir — avoids cross-model cache hits
        safe_model = model.replace("/", "_").replace("\\", "_").replace(" ", "_")
        self._cache_dir = os.path.join(output_dir, ".llm_cache", safe_model)
        os.makedirs(self._cache_dir, exist_ok=True)

    def _make_reasoning(self) -> VulnerabilityAnalyzer:
        a = VulnerabilityAnalyzer(
            base_url=self._base_url,
            api_key=self._api_key,
            output_dir=self._cache_dir,
            model=self._model,
        )
        _patch_for_provider(a, self._base_url)
        return a

    def _make_direct(self) -> VulnerabilityAnalyzerWeakPrompt:
        a = VulnerabilityAnalyzerWeakPrompt(
            base_url=self._base_url,
            api_key=self._api_key,
            output_dir=self._cache_dir,
            model=self._model,
        )
        # Direct prompt doesn't have extra_body, but patch anyway for safety
        return a

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def analyze_one(
        self,
        vuln_info: dict[str, Any],
        code_content: str,
        mode: str = "reasoning",
    ) -> dict[str, Any]:
        """Analyze a single vulnerability path.

        Returns
        -------
        dict with keys: is_vulnerable, reasoning_chain, analysis_result, error, ...
        """
        analyzer = self._make_reasoning() if mode == "reasoning" else self._make_direct()

        c_hash = _code_hash(code_content, vuln_info)
        existing = analyzer.check_existing_analysis(c_hash)
        if existing:
            return existing

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", encoding="utf-8", delete=False,
        ) as tmp:
            tmp.write(code_content)
            tmp_path = tmp.name

        try:
            result = analyzer.analyze_vulnerability_path(vuln_info, tmp_path)
            # Detect authentication errors from the result text
            if isinstance(result, dict):
                reasoning = result.get("reasoning_chain", "") or result.get("analysis_result", "")
                if _is_auth_error(reasoning):
                    result["error"] = "API key 无效或认证失败。请检查 Settings 中的 API Key 是否正确。"
                    result["is_vulnerable"] = False
            return result
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def analyze_batch(
        self,
        items: list[dict[str, Any]],
        mode: str = "reasoning",
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze a batch of vulnerability paths.

        Parameters
        ----------
        items : list of dict
            Each dict must have keys: ``result_id``, ``vuln_info``, ``code_content``.
        mode : str
            ``"direct"`` or ``"reasoning"``.
        on_progress : callable or None
            Called after each item: ``on_progress(completed, total, current_id)``.

        Returns
        -------
        list of dict
            Each: ``{result_id, vuln_info, verdict}``
        """
        results: list[dict[str, Any]] = []
        total = len(items)
        for i, item in enumerate(items):
            if on_progress:
                on_progress(i + 1, total, item.get("result_id", ""))
            verdict = self.analyze_one(
                vuln_info=item["vuln_info"],
                code_content=item["code_content"],
                mode=mode,
            )
            results.append({
                "result_id": item.get("result_id", ""),
                "vuln_info": item["vuln_info"],
                "verdict": verdict,
            })
        return results


def _is_auth_error(text: str) -> bool:
    """Check if the LLM returned an authentication / authorization error."""
    if not text:
        return False
    lower = text.lower()
    indicators = [
        "401", "unauthorized", "invalid api key",
        "authentication failed", "incorrect api key",
        "invalid x-api-key", "you didn't provide an api key",
        "status code 401", "http 401",
    ]
    return any(ind in lower for ind in indicators)
