"""Project-wide constants for backward analysis.

This module isolates Hex-Rays operator constants to gracefully survive
minor IDA SDK differences.
"""
from __future__ import annotations

from typing import Set

try:
    import idaapi  # type: ignore
except Exception:  # pragma: no cover - only available inside IDA
    idaapi = None  # type: ignore

ASSIGN_OP_NAMES = [
    "cot_asg",     # =
    "cot_asgadd",  # +=
    "cot_asgsub",  # -=
    "cot_asgmul",  # *=
    "cot_asgsshr", # >>=
    "cot_asgushr", # >>>=
    "cot_asgshl",  # <<=
    "cot_asgsdiv", # /= (signed)
    "cot_asgudiv", # /= (unsigned)
    "cot_asgsmod", # %= (signed)
    "cot_asgumod", # %= (unsigned)
    "cot_asgbor",  # |=
    "cot_asgxor",  # ^=
    "cot_asgband", # &=
    "cot_init",    # initializer
]


def build_assign_ops() -> Set[int]:
    """Build the set of Hex-Rays assignment-like ops present in this IDA.

    Returns:
        Set[int]: A set of operator enums available at runtime.
    """
    ops: Set[int] = set()
    if idaapi is None:
        return ops
    for name in ASSIGN_OP_NAMES:
        if hasattr(idaapi, name):
            ops.add(getattr(idaapi, name))
    if not ops and hasattr(idaapi, "cot_asg"):
        ops = {getattr(idaapi, "cot_asg")}
    return ops


ASSIGN_OPS = build_assign_ops()