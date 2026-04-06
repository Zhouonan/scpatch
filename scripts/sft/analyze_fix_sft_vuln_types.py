\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
   

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


DEFAULT_ALLOWED_TYPES: List[str] = [
    "REENTRANCY",
    "ACCESS_CONTROL",
    "ARITHMETIC",
    "UNCHECKED_CALL",
    "BAD_RANDOMNESS",
    "FRONT_RUNNING",
    "DOS",
    "TX_ORIGIN",
    "TIMESTAMP_DEPENDENCE",
    "DELEGATECALL",
    "UNINITIALIZED_STORAGE",
    "STORAGE_CORRUPTION",
]

                                                                                              
DEFAULT_TYPE_SYNONYMS: Dict[str, str] = {
                
    "reentrancy": "REENTRANCY",
    "reentrancy-eth": "REENTRANCY",
    "re-entrancy": "REENTRANCY",
                    
    "access control": "ACCESS_CONTROL",
    "authorization": "ACCESS_CONTROL",
    "auth": "ACCESS_CONTROL",
                
    "integer overflow/underflow": "ARITHMETIC",
    "integer overflow": "ARITHMETIC",
    "integer underflow": "ARITHMETIC",
    "overflow": "ARITHMETIC",
    "underflow": "ARITHMETIC",
    "arithmetic": "ARITHMETIC",
    "arithmetic error": "ARITHMETIC",
                    
    "unchecked low-level calls": "UNCHECKED_CALL",
    "unchecked low level calls": "UNCHECKED_CALL",
    "unchecked call": "UNCHECKED_CALL",
    "unchecked return value": "UNCHECKED_CALL",
                
    "bad randomness": "BAD_RANDOMNESS",
    "predictable game outcome": "BAD_RANDOMNESS",
    "weak randomness": "BAD_RANDOMNESS",
                   
    "front running": "FRONT_RUNNING",
    "front-running": "FRONT_RUNNING",
    "transaction ordering dependence": "FRONT_RUNNING",
    "tod": "FRONT_RUNNING",
         
    "denial of service": "DOS",
    "dos": "DOS",
               
    "tx.origin": "TX_ORIGIN",
    "tx origin": "TX_ORIGIN",
    "tx_origin": "TX_ORIGIN",
                          
    "timestamp dependence": "TIMESTAMP_DEPENDENCE",
    "block.timestamp dependence": "TIMESTAMP_DEPENDENCE",
    "time manipulation": "TIMESTAMP_DEPENDENCE",
    "miner manipulation": "TIMESTAMP_DEPENDENCE",
                  
    "delegatecall": "DELEGATECALL",
                    
    "uninitialized storage pointer": "UNINITIALIZED_STORAGE",
    "uninitialized storage": "UNINITIALIZED_STORAGE",
    "uninitialized state": "UNINITIALIZED_STORAGE",
    "storage corruption": "STORAGE_CORRUPTION",
}


VULN_TYPE_RE = re.compile(r"(?mi)^\s*-\s*Type:\s*(.+?)\s*$")


def _extract_vuln_types_from_input(input_text: str) -> List[str]:
    m = VULN_TYPE_RE.search(input_text or "")
    if not m:
        return []
    raw = m.group(1).strip()
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def _normalize_vuln_type_one(t: str, synonyms: Dict[str, str], allowed: List[str]) -> Optional[str]:
    if not t:
        return None
    key = t.strip().lower()
    key = re.sub(r"\s+", " ", key)
    key = key.replace("_", " ").replace("-", " ")
    key = re.sub(r"\s+", " ", key).strip()
    if key in synonyms:
        canon = synonyms[key]
        return canon if canon in allowed else None
                                                                                
                                                                
    if "reentr" in key:
        return "REENTRANCY" if "REENTRANCY" in allowed else None
    if "access control" in key or "authorization" in key or "authentication" in key or key.startswith("auth "):
        return "ACCESS_CONTROL" if "ACCESS_CONTROL" in allowed else None
    if (
        "overflow" in key
        or "underflow" in key
        or "precision" in key
        or "division" in key
        or "rounding" in key
        or "truncation" in key
        or "arithmetic" in key
        or "math" in key
        or "calculation" in key
    ):
        return "ARITHMETIC" if "ARITHMETIC" in allowed else None
    if (
        "unchecked" in key
        or "low level call" in key
        or "low-level call" in key
        or "external call" in key
        or "call return" in key
        or "send" in key
        or "transfer" in key
    ):
        return "UNCHECKED_CALL" if "UNCHECKED_CALL" in allowed else None
    if "random" in key or "prng" in key or "predictable" in key:
        return "BAD_RANDOMNESS" if "BAD_RANDOMNESS" in allowed else None
    if "front run" in key or "front-running" in key or "transaction ordering" in key or key == "tod":
        return "FRONT_RUNNING" if "FRONT_RUNNING" in allowed else None
    if (
        "denial of service" in key
        or key == "dos"
        or "gas exhaustion" in key
        or "gas grief" in key
        or "gas consumption" in key
        or "unbounded loop" in key
        or "infinite loop" in key
        or "gas limit" in key
    ):
        return "DOS" if "DOS" in allowed else None
    if "tx.origin" in key or "tx origin" in key:
        return "TX_ORIGIN" if "TX_ORIGIN" in allowed else None
    if "timestamp" in key or "time manipulation" in key or "miner manipulation" in key or "block variable" in key:
        return "TIMESTAMP_DEPENDENCE" if "TIMESTAMP_DEPENDENCE" in allowed else None
    if "delegatecall" in key:
        return "DELEGATECALL" if "DELEGATECALL" in allowed else None
    if "uninitialized" in key and ("storage" in key or "state" in key or "init" in key or "initialization" in key):
        return "UNINITIALIZED_STORAGE" if "UNINITIALIZED_STORAGE" in allowed else None
    if "storage" in key and ("corruption" in key or "collision" in key or "overwrite" in key or "out of bounds" in key):
        return "STORAGE_CORRUPTION" if "STORAGE_CORRUPTION" in allowed else None
                                       
    canon_guess = re.sub(r"[^a-z0-9]+", "_", key).strip("_").upper()
    if canon_guess in allowed:
        return canon_guess
    return None


def _normalize_vuln_types(raw_types: List[str], synonyms: Dict[str, str], allowed: List[str]) -> List[str]:
    out: List[str] = []
    for t in raw_types:
        canon = _normalize_vuln_type_one(t, synonyms, allowed)
        if canon and canon not in out:
            out.append(canon)
    return out


@dataclass
class AnalyzeResult:
    total: int
    missing_type: int
    unmappable: int
    raw_type_counts: Dict[str, int]
    norm_type_counts: Dict[str, int]
    raw_to_norm_counts: Dict[str, Dict[str, int]]
    unmappable_raw_type_counts: Dict[str, int]
    multi_label_samples: int


def analyze_jsonl(path: Path, allowed: List[str], synonyms: Dict[str, str]) -> AnalyzeResult:
    total = 0
    missing_type = 0
    unmappable = 0
    multi_label_samples = 0

    raw_counter: Counter[str] = Counter()
    norm_counter: Counter[str] = Counter()
    unmappable_raw: Counter[str] = Counter()

    raw_to_norm: Dict[str, Counter[str]] = defaultdict(Counter)

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                obj = json.loads(line)
            except Exception:
                                                
                continue
            raw_types = _extract_vuln_types_from_input(str(obj.get("input", "")))
            if not raw_types:
                missing_type += 1
                continue

            if len(raw_types) > 1:
                multi_label_samples += 1

            for rt in raw_types:
                raw_counter[rt] += 1

            norm_types = _normalize_vuln_types(raw_types, synonyms, allowed)
            if not norm_types:
                unmappable += 1
                for rt in raw_types:
                    unmappable_raw[rt] += 1
                continue

            for nt in norm_types:
                norm_counter[nt] += 1
            for rt in raw_types:
                nt = _normalize_vuln_type_one(rt, synonyms, allowed)
                raw_to_norm[rt][nt or "__UNMAPPABLE__"] += 1

    return AnalyzeResult(
        total=total,
        missing_type=missing_type,
        unmappable=unmappable,
        raw_type_counts=dict(raw_counter.most_common()),
        norm_type_counts=dict(norm_counter.most_common()),
        raw_to_norm_counts={k: dict(v.most_common()) for k, v in raw_to_norm.items()},
        unmappable_raw_type_counts=dict(unmappable_raw.most_common()),
        multi_label_samples=multi_label_samples,
    )


def write_id_map(path_in: Path, path_out: Path, allowed: List[str], synonyms: Dict[str, str]) -> None:
    path_out.parent.mkdir(parents=True, exist_ok=True)
    with open(path_in, "r", encoding="utf-8") as fin, open(path_out, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            sid = obj.get("id")
            raw_types = _extract_vuln_types_from_input(str(obj.get("input", "")))
            norm_types = _normalize_vuln_types(raw_types, synonyms, allowed) if raw_types else []
            fout.write(
                json.dumps(
                    {
                        "id": sid,
                        "raw_types": raw_types,
                        "norm_types": norm_types,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input JSONL path (Fix-SFT samples).")
    parser.add_argument("--report-out", default="", help="Write JSON report to this path.")
    parser.add_argument("--id-map-out", default="", help="Write id->type sidecar JSONL to this path.")
    args = parser.parse_args()

    in_path = Path(args.input)
    allowed = list(DEFAULT_ALLOWED_TYPES)
    synonyms = dict(DEFAULT_TYPE_SYNONYMS)

    res = analyze_jsonl(in_path, allowed=allowed, synonyms=synonyms)

    report = {
        "input": str(in_path),
        "allowed_types": allowed,
        "summary": {
            "total_samples": res.total,
            "missing_type_samples": res.missing_type,
            "unmappable_samples": res.unmappable,
            "multi_label_samples": res.multi_label_samples,
            "raw_type_vocab_size": len(res.raw_type_counts),
            "norm_type_vocab_size": len(res.norm_type_counts),
        },
        "raw_type_counts": res.raw_type_counts,
        "norm_type_counts": res.norm_type_counts,
        "unmappable_raw_type_counts": res.unmappable_raw_type_counts,
        "raw_to_norm_counts": res.raw_to_norm_counts,
    }

    if args.report_out:
        out_path = Path(args.report_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    else:
        print(json.dumps(report["summary"], indent=2, ensure_ascii=False))

    if args.id_map_out:
        write_id_map(in_path, Path(args.id_map_out), allowed=allowed, synonyms=synonyms)


if __name__ == "__main__":
    main()


