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
from typing import Dict, List, Optional, Set, Tuple, Any


VULN_TYPE_RE = re.compile(r"(?mi)^\s*-\s*Type:\s*(.+?)\s*$")


def extract_raw_types(input_text: str) -> List[str]:
    m = VULN_TYPE_RE.search(input_text or "")
    if not m:
        return []
    raw = m.group(1).strip()
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def _norm_key(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    s = s.replace("_", " ").replace("-", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


                                                                         
SWC_TITLES: Dict[str, str] = {
    "SWC-101": "Integer Overflow and Underflow",
    "SWC-104": "Unchecked Call Return Value",
    "SWC-106": "Unprotected SELFDESTRUCT Instruction",
    "SWC-107": "Reentrancy",
    "SWC-109": "Uninitialized Storage Pointer",
    "SWC-110": "Assert Violation",
    "SWC-111": "Use of Deprecated Solidity Functions",
    "SWC-112": "Delegatecall to Untrusted Callee",
    "SWC-113": "DoS with Failed Call",
    "SWC-114": "Transaction Order Dependence",
    "SWC-115": "Authorization through tx.origin",
    "SWC-116": "Block values as a proxy for time",
    "SWC-117": "Signature Malleability",
    "SWC-120": "Weak Sources of Randomness from Chain Attributes",
    "SWC-121": "Missing Protection against Signature Replay Attacks",
    "SWC-122": "Lack of Proper Signature Verification",
    "SWC-124": "Write to Arbitrary Storage Location",
    "SWC-126": "Insufficient Gas Griefing",
    "SWC-128": "DoS With Block Gas Limit",
    "SWC-132": "Unexpected Ether Balance",
    "SWC-133": "Hash Collisions With Multiple Variable Length Arguments",
}


def map_raw_type_to_swcs(raw_type: str) -> Set[str]:
\
\
\
       
    key = _norm_key(raw_type)
    out: Set[str] = set()

                                         
    if "overflow" in key or "underflow" in key or "arithmetic" in key:
        out.add("SWC-101")
    if "unchecked" in key and ("call" in key or "return" in key):
        out.add("SWC-104")
    if "selfdestruct" in key or "contract destruction" in key or "unchecked selfdestruct" in key:
        out.add("SWC-106")
    if "reentr" in key:
        out.add("SWC-107")
    if "tx origin" in key or "tx.origin" in key:
        out.add("SWC-115")

                                                        
    if "uninitialized storage" in key or "uninitialized storage pointer" in key or "storage pointer misuse" in key:
        out.add("SWC-109")
    if "assert" in key:
        out.add("SWC-110")
    if "deprecated" in key or "throw" in key:
        out.add("SWC-111")
    if "delegatecall" in key:
        out.add("SWC-112")

                  
    if "gas grief" in key:
        out.add("SWC-126")
    if "block gas" in key or "gas limit" in key or "gas exhaustion" in key or "unbounded loop" in key or "infinite loop" in key:
        out.add("SWC-128")
    if "dos" in key or "denial of service" in key or "failed send" in key or "failed call" in key:
        out.add("SWC-113")

                                         
    if "front run" in key or "front-running" in key or "transaction ordering" in key or key == "tod":
        out.add("SWC-114")

                                 
    if "timestamp" in key or "time manipulation" in key or "miner manipulation" in key or "block variable" in key:
        out.add("SWC-116")

                
    if "random" in key or "prng" in key or "predictable" in key:
        out.add("SWC-120")

                                   
    if "signature malleability" in key:
        out.add("SWC-117")
    if "replay attack" in key or "signature replay" in key:
        out.add("SWC-121")
    if "signature verification" in key:
        out.add("SWC-122")

                              
    if (
        "arbitrary storage write" in key
        or "write to arbitrary storage" in key
        or "arbitrary write" in key
        or "storage corruption" in key
        or "storage collision" in key
        or "out of bounds write" in key
        or "state variable overwrite" in key
        or "state variable corruption" in key
    ):
        out.add("SWC-124")

                                  
    if "forced ether reception" in key or "unexpected ether" in key:
        out.add("SWC-132")

                     
    if "hash collision" in key:
        out.add("SWC-133")

    return out


@dataclass
class SwcReport:
    total_samples: int
    missing_type_samples: int
    excluded_swcs: List[str]
    swc_sample_counts: Dict[str, int]
    swc_label_counts: Dict[str, int]
    swc_to_raw_examples: Dict[str, List[str]]
    unmapped_raw_type_counts: Dict[str, int]


def analyze(input_path: Path, exclude_swcs: Set[str], max_examples_per_swc: int = 30) -> SwcReport:
    total_samples = 0
    missing_type_samples = 0

    swc_sample_counter: Counter[str] = Counter()
    swc_label_counter: Counter[str] = Counter()
    swc_to_raw: Dict[str, List[str]] = defaultdict(list)
    unmapped_raw: Counter[str] = Counter()

    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_samples += 1
            try:
                obj = json.loads(line)
            except Exception:
                continue

            raw_types = extract_raw_types(str(obj.get("input", "")))
            if not raw_types:
                missing_type_samples += 1
                continue

            swcs_in_sample: Set[str] = set()
            for rt in raw_types:
                swcs = map_raw_type_to_swcs(rt)
                swcs = {s for s in swcs if s not in exclude_swcs}
                if not swcs:
                    unmapped_raw[rt] += 1
                    continue
                for swc in swcs:
                    swc_label_counter[swc] += 1
                    if len(swc_to_raw[swc]) < max_examples_per_swc and rt not in swc_to_raw[swc]:
                        swc_to_raw[swc].append(rt)
                    swcs_in_sample.add(swc)

            for swc in swcs_in_sample:
                swc_sample_counter[swc] += 1

                                
    swc_sample_counts = dict(swc_sample_counter.most_common())
    swc_label_counts = dict(swc_label_counter.most_common())
    unmapped_raw_type_counts = dict(unmapped_raw.most_common())

                                                        
    swc_to_raw_examples = {k: swc_to_raw[k] for k in swc_sample_counts.keys()}

    return SwcReport(
        total_samples=total_samples,
        missing_type_samples=missing_type_samples,
        excluded_swcs=sorted(exclude_swcs),
        swc_sample_counts=swc_sample_counts,
        swc_label_counts=swc_label_counts,
        swc_to_raw_examples=swc_to_raw_examples,
        unmapped_raw_type_counts=unmapped_raw_type_counts,
    )


def write_id_map(input_path: Path, out_path: Path, exclude_swcs: Set[str]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(input_path, "r", encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            sid = obj.get("id")
            raw_types = extract_raw_types(str(obj.get("input", "")))
            swcs: Set[str] = set()
            for rt in raw_types:
                swcs |= {s for s in map_raw_type_to_swcs(rt) if s not in exclude_swcs}
            fout.write(
                json.dumps(
                    {
                        "id": sid,
                        "raw_types": raw_types,
                        "swcs": sorted(swcs),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def _parse_exclude_swc(arg: str) -> Set[str]:
    if not arg:
        return set()
    out: Set[str] = set()
    for p in arg.split(","):
        p = p.strip()
        if not p:
            continue
        if p.startswith("SWC-"):
            out.add(p)
        else:
            out.add(f"SWC-{int(p):03d}")
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input Fix-SFT JSONL.")
    parser.add_argument("--exclude-swc", default="", help="Comma separated SWC IDs or numbers, e.g. 101,104,106.")
    parser.add_argument("--report-out", default="", help="Write JSON report to this path.")
    parser.add_argument("--id-map-out", default="", help="Write per-id SWC mapping JSONL to this path.")
    args = parser.parse_args()

    input_path = Path(args.input)
    exclude = _parse_exclude_swc(args.exclude_swc)

    rep = analyze(input_path, exclude_swcs=exclude)
    report_obj = {
        "input": str(input_path),
        "excluded_swcs": rep.excluded_swcs,
        "swc_titles": {k: SWC_TITLES.get(k, "") for k in rep.swc_sample_counts.keys()},
        "summary": {
            "total_samples": rep.total_samples,
            "missing_type_samples": rep.missing_type_samples,
            "mapped_swc_vocab_size": len(rep.swc_sample_counts),
            "unmapped_raw_type_vocab_size": len(rep.unmapped_raw_type_counts),
        },
        "swc_sample_counts": rep.swc_sample_counts,
        "swc_label_counts": rep.swc_label_counts,
        "swc_to_raw_examples": rep.swc_to_raw_examples,
        "unmapped_raw_type_counts": rep.unmapped_raw_type_counts,
    }

    if args.report_out:
        out_path = Path(args.report_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_obj, f, indent=2, ensure_ascii=False)
    else:
        print(json.dumps(report_obj["summary"], indent=2, ensure_ascii=False))

    if args.id_map_out:
        write_id_map(input_path, Path(args.id_map_out), exclude_swcs=exclude)


if __name__ == "__main__":
    main()


