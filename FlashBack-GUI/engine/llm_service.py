# coding: utf-8
"""LLM analyzer service adapter.

Wraps the standalone VulnerabilityAnalyzer (Reasoning-Guided) and
VulnerabilityAnalyzerWeakPrompt (Direct) classes so they can be called
with in-memory code content instead of disk file paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

# Allow importing from resources/llm/
_RESOURCE_LLM = (
    Path(__file__).resolve().parent.parent / "resources" / "llm"
)
if str(_RESOURCE_LLM) not in sys.path:
    sys.path.insert(0, str(_RESOURCE_LLM))

from LLM_Direct_Prompt import VulnerabilityAnalyzerWeakPrompt  # noqa: E402
from LLM_Reasoning_Guided import VulnerabilityAnalyzer  # noqa: E402


def _code_hash(code_content: str, vuln_info: dict[str, Any]) -> str:
    raw = code_content + json.dumps(vuln_info, sort_keys=True, default=str)
    return hashlib.md5(raw.encode()).hexdigest()


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
        self._output_dir = output_dir

    def _make_reasoning(self) -> VulnerabilityAnalyzer:
        return VulnerabilityAnalyzer(
            base_url=self._base_url,
            api_key=self._api_key,
            output_dir=self._output_dir,
            model=self._model,
        )

    def _make_direct(self) -> VulnerabilityAnalyzerWeakPrompt:
        return VulnerabilityAnalyzerWeakPrompt(
            base_url=self._base_url,
            api_key=self._api_key,
            output_dir=self._output_dir,
            model=self._model,
        )

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

        The existing analyzers read code from disk; we bridge this by
        writing *code_content* to a temp .c file, calling the original
        method, then cleaning up.

        Returns
        -------
        dict with keys: is_vulnerable, reasoning_chain, analysis_result, ...
        """
        analyzer = self._make_reasoning() if mode == "reasoning" else self._make_direct()

        # Fast cache hit via the analyzer's built-in SQLite cache
        c_hash = _code_hash(code_content, vuln_info)
        existing = analyzer.check_existing_analysis(c_hash)
        if existing:
            return existing

        # Write temp file, call analyzer, clean up
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".c",
            encoding="utf-8",
            delete=False,
        ) as tmp:
            tmp.write(code_content)
            tmp_path = tmp.name

        try:
            return analyzer.analyze_vulnerability_path(vuln_info, tmp_path)
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
