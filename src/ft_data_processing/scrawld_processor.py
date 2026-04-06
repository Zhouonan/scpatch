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

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from tqdm import tqdm

from src.ft_data_processing.smartbugs_processor import ContractInfo


ScrawlDLoc = Union[int, str]                                              


@dataclass(frozen=True)
class VulnSpec:
                   

                           
    key: str
                                
    name: str
                                                                             
    category: str
                                                                   
    threshold: int
                                         
    scrawld_tokens: Tuple[str, ...]
                                                                 
    location_kind: str                       


VULN_SPECS: Tuple[VulnSpec, ...] = (
    VulnSpec(
        key="ARITHMETIC_OVERFLOW_UNDERFLOW",
        name="Arithmetic (Integer Overflow and Underflow)",
        category="arithmetic",
        threshold=2,
        scrawld_tokens=("ARTHM",),
        location_kind="line",
    ),
    VulnSpec(
        key="DENIAL_OF_SERVICE",
        name="Denial of Service",
        category="denial_of_service",
        threshold=1,
        scrawld_tokens=("DOS",),
        location_kind="line",
    ),
    VulnSpec(
        key="REENTRANCY",
        name="Reentrancy",
        category="reentrancy",
        threshold=2,
        scrawld_tokens=("RENT",),
        location_kind="function",
    ),
    VulnSpec(
        key="TIME_MANIPULATION",
        name="Time Manipulation (Block values as a proxy for time)",
        category="time_manipulation",
        threshold=2,
        scrawld_tokens=("TimeM",),
        location_kind="line",
    ),
    VulnSpec(
        key="TIMESTAMP_ORDERING",
        name="Timestamp Ordering (Transaction Order Dependence)",
        category="front_running",
        threshold=1,
        scrawld_tokens=("TimeO",),
        location_kind="line",
    ),
    VulnSpec(
        key="TX_ORIGIN_AUTHORIZATION",
        name="Authorization through tx.origin",
        category="access_control",
        threshold=2,
        scrawld_tokens=("Tx-Origin", "TX-Origin"),
        location_kind="line",
    ),
    VulnSpec(
        key="UNCHECKED_CALL_RETURN_VALUE",
        name="Unhandled Exception (Unchecked Call Return Value)",
        category="unchecked_low_level_calls",
        threshold=1,
        scrawld_tokens=("UE",),
        location_kind="line",
    ),
)


TOKEN_TO_SPEC: Dict[str, VulnSpec] = {
    tok: spec for spec in VULN_SPECS for tok in spec.scrawld_tokens
}


def _extract_solidity_version(code: str) -> str:
    patterns = [
        r"pragma\s+solidity\s+\^?([0-9]+\.[0-9]+\.[0-9]+)",
        r"pragma\s+solidity\s+>=?([0-9]+\.[0-9]+\.[0-9]+)",
        r"pragma\s+solidity\s+([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    for pat in patterns:
        m = re.search(pat, code)
        if m:
            return m.group(1)
    return "0.4.25"


def _line_start_offsets(code: str) -> List[int]:
                                                                          
    offsets = [0]
    for i, ch in enumerate(code):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _slice_by_lines(code: str, line_offsets: List[int], start_line: int, end_line: int) -> str:
    if start_line < 1:
        start_line = 1
    if end_line < start_line:
        end_line = start_line
    start_idx = line_offsets[start_line - 1] if start_line - 1 < len(line_offsets) else 0
                                                                     
    next_line_idx = end_line if end_line < len(line_offsets) else None
    end_idx = line_offsets[next_line_idx] if next_line_idx is not None else len(code)
    return code[start_idx:end_idx]


def _parse_function_lines(function_lines_path: Path) -> Dict[str, List[Tuple[str, int, int]]]:
\
\
\
\
\
\
       
    mapping: Dict[str, List[Tuple[str, int, int]]] = {}
    with function_lines_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                                                      
            parts = line.split(";")
            if len(parts) != 4:
                continue
            file_part, func_sig, start_s, end_s = parts
            file_part = file_part.strip()
            if file_part.startswith("./"):
                file_part = file_part[2:]
            contract_file = Path(file_part).name
            try:
                start_line = int(start_s)
                end_line = int(end_s)
            except ValueError:
                continue
            mapping.setdefault(contract_file, []).append((func_sig.strip(), start_line, end_line))
    return mapping


def _parse_scrawld_res_all(
    res_all_path: Path,
) -> Dict[str, Dict[str, Dict[ScrawlDLoc, Set[str]]]]:
\
\
\
\
\
\
\
\
       
    out: Dict[str, Dict[str, Dict[ScrawlDLoc, Set[str]]]] = {}
    with res_all_path.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split()
            if len(parts) < 3:
                continue
            contract_file = parts[0].strip()
            vuln_tok = parts[1].strip()
            if vuln_tok == "LE":
                continue                      
            spec = TOKEN_TO_SPEC.get(vuln_tok)
            if not spec:
                continue
            tool = parts[-1].strip()

            location: ScrawlDLoc
            if spec.location_kind == "function":
                                                                 
                if len(parts) < 4:
                    continue
                location = " ".join(parts[2:-1]).strip()
                if not location:
                    continue
            else:
                                               
                if len(parts) < 4:
                    continue
                try:
                    location = int(parts[2])
                except ValueError:
                    continue

            out.setdefault(contract_file, {}).setdefault(spec.key, {}).setdefault(location, set()).add(tool)
    return out


def _function_name_from_signature(func_sig: str) -> str:
                                                                                                                          
                                                               
    s = func_sig.strip()
    if "(" in s:
        s = s.split("(", 1)[0]
    if "." in s:
        s = s.split(".")[-1]
    return s.strip() or "unknown"


class ScrawlDProcessor:
                                           

    def __init__(
        self,
        scrawld_dir: str,
        output_dir: str = "./processed_data",
        thresholds: Optional[Dict[str, int]] = None,
        include_unknown_mappings: bool = False,
    ):
        self.scrawld_dir = Path(scrawld_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.contract_dir = self.scrawld_dir / "classified_contracts_dos1/DOS/single"
        self.data_dir = self.scrawld_dir / "data"
        self.res_all_path = self.data_dir / "scrawld_res_all.txt"
        self.function_lines_path = self.data_dir / "function_lines.txt"

        if not self.contract_dir.exists():
            raise FileNotFoundError(f"Missing ScrawlD contract dir: {self.contract_dir}")
        if not self.res_all_path.exists():
            raise FileNotFoundError(f"Missing ScrawlD res_all file: {self.res_all_path}")
        if not self.function_lines_path.exists():
            raise FileNotFoundError(f"Missing ScrawlD function_lines file: {self.function_lines_path}")

                                                                 
        self.thresholds: Dict[str, int] = {spec.key: spec.threshold for spec in VULN_SPECS}
        if thresholds:
            self.thresholds.update(thresholds)

        self.include_unknown_mappings = include_unknown_mappings

                           
        self._func_ranges = _parse_function_lines(self.function_lines_path)
        self._raw_findings = _parse_scrawld_res_all(self.res_all_path)

    def _apply_thresholds(
        self, contract_file: str
    ) -> Dict[str, List[Tuple[ScrawlDLoc, Set[str]]]]:
\
\
\
\
\
           
        per = self._raw_findings.get(contract_file, {})
        out: Dict[str, List[Tuple[ScrawlDLoc, Set[str]]]] = {}
        for vuln_key, loc_map in per.items():
            thr = int(self.thresholds.get(vuln_key, 1))
            for loc, tools in loc_map.items():
                if len(tools) >= thr:
                    out.setdefault(vuln_key, []).append((loc, tools))
        return out

    def process_scrawld(self, sample_size: Optional[int] = None) -> List[ContractInfo]:
                                           
        sol_files = sorted(self.contract_dir.glob("*_ext.sol"))
        if sample_size:
            sol_files = sol_files[: min(sample_size, len(sol_files))]

        contracts: List[ContractInfo] = []

        for sol_file in tqdm(sol_files, desc="  处理 ScrawlD"):
            try:
                code = sol_file.read_text(encoding="utf-8", errors="ignore")
                version = _extract_solidity_version(code)
                line_offsets = _line_start_offsets(code)

                contract_filename = sol_file.name
                addr = sol_file.stem.replace("_ext", "")

                                                             
                ranges = self._func_ranges.get(contract_filename, [])

                                        
                functions: List[Dict] = []
                sig_to_idx: Dict[str, int] = {}

                for func_sig, start_line, end_line in ranges:
                    name = _function_name_from_signature(func_sig)
                    func_code = _slice_by_lines(code, line_offsets, start_line, end_line)
                    func_obj = {
                        "name": name,
                        "signature": func_sig,
                        "code": func_code,
                        "lines": [start_line, end_line],
                        "vulnerabilities": [],
                        "is_vulnerable": False,
                    }
                    sig_to_idx[func_sig] = len(functions)
                    functions.append(func_obj)

                                                                                                    
                                                    
                findings = self._apply_thresholds(contract_filename)

                                                                                
                def add_vuln(func: Dict, spec: VulnSpec, lines: List[int], tools: Set[str], raw_type: str):
                                                  
                    for v in func["vulnerabilities"]:
                        if v.get("category") == spec.category and v.get("raw_type") == raw_type:
                            v["lines"] = sorted(set(v.get("lines", [])) | set(lines))
                            v["tools"] = sorted(set(v.get("tools", [])) | set(tools))
                            return
                    func["vulnerabilities"].append(
                        {
                            "category": spec.category,
                            "name": spec.name,
                            "raw_type": raw_type,
                            "lines": sorted(set(lines)),
                            "tools": sorted(set(tools)),
                        }
                    )

                                                      
                intervals: List[Tuple[int, int, int]] = []
                for idx, fobj in enumerate(functions):
                    l = fobj.get("lines") or []
                    if len(l) >= 2:
                        intervals.append((int(l[0]), int(l[1]), idx))

                for vuln_key, items in findings.items():
                    spec = next((s for s in VULN_SPECS if s.key == vuln_key), None)
                    if not spec:
                        continue

                    if spec.location_kind == "function":
                        for loc, tools in items:
                            if not isinstance(loc, str):
                                continue
                            idx = sig_to_idx.get(loc)
                            if idx is None:
                                if self.include_unknown_mappings:
                                                                 
                                    pass
                                continue
                            fobj = functions[idx]
                            start_line = (fobj.get("lines") or [1])[0]
                            add_vuln(fobj, spec, [int(start_line)], tools, raw_type=vuln_key)
                    else:
                        for loc, tools in items:
                            if not isinstance(loc, int):
                                continue
                                                                                  
                            hit = False
                            for s_line, e_line, idx in intervals:
                                if s_line <= loc <= e_line:
                                    add_vuln(functions[idx], spec, [loc], tools, raw_type=vuln_key)
                                    hit = True
                            if not hit and self.include_unknown_mappings:
                                                          
                                pass

                                              
                contract_vuln_types: Set[str] = set()
                contract_vuln_names: Set[str] = set()
                for fobj in functions:
                    if fobj["vulnerabilities"]:
                        fobj["is_vulnerable"] = True
                        for v in fobj["vulnerabilities"]:
                            contract_vuln_types.add(v["category"])
                            contract_vuln_names.add(v["name"])

                contract_label = {
                    "has_vulnerability": len(contract_vuln_types) > 0,
                    "vulnerability_types": sorted(contract_vuln_types),
                    "vulnerability_names": sorted(contract_vuln_names),
                    "source": "scrawld_res_all",
                    "thresholds": {k: int(v) for k, v in self.thresholds.items()},
                }

                contract = ContractInfo(
                    file_path=str(sol_file),
                    contract_name=sol_file.stem,
                    solidity_version=version,
                    functions=functions,
                    label=contract_label,
                    metadata={
                        "dataset": "scrawld",
                        "ground_truth": True,
                        "address": addr,
                    },
                )
                contracts.append(contract)

            except Exception as e:
                                                   
                continue

        return contracts

    def save_contracts(self, contracts: List[ContractInfo], filename: str) -> None:
        output_file = self.output_dir / filename
        data = []
        for c in contracts:
            data.append(
                {
                    "file_path": c.file_path,
                    "contract_name": c.contract_name,
                    "solidity_version": c.solidity_version,
                    "num_functions": len(c.functions),
                    "functions": c.functions,
                    "label": c.label,
                    "metadata": c.metadata,
                }
            )
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


