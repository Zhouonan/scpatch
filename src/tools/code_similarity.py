from __future__ import annotations
import difflib
from typing import List

def normalize_code_for_similarity(code: str) -> str:
    if not code:
        return ''
    lines: List[str] = []
    for ln in str(code).splitlines():
        s = ln.strip()
        if not s:
            continue
        lines.append(s)
    return '\n'.join(lines).strip()

def text_similarity(a: str, b: str) -> float:
    na = normalize_code_for_similarity(a)
    nb = normalize_code_for_similarity(b)
    if not na and (not nb):
        return 1.0
    if not na or not nb:
        return 0.0
    return float(difflib.SequenceMatcher(a=na, b=nb).ratio())
