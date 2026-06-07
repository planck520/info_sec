# coding: utf-8
"""结果查询 + 导出路由 — 成员 B 实现。
🔴5 result_id = {device}/{firmware}/{path_index} 三段式。
"""

from fastapi import APIRouter

router = APIRouter(tags=["results"])

# 成员 B 在此添加 /api/results/* 端点
