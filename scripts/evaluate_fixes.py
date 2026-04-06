\
\
\
\
   

import sys
import os
import json
import argparse
import re
import time
import traceback
import difflib
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Future, as_completed

            
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.evaluation.metrics import compute_metrics, calculate_pass_at_k
from tqdm import tqdm                

                                                       
                                                                                      
BUCKET_ORDER = [
    "REENTRANCY",
    "ACCESS_CONTROL",
    "UNCHECKED_CALL",
    "ARITHMETIC",
    "BAD_RANDOMNESS",
    "TIMESTAMP_DEPENDENCE",
    "DOS",
    "STORAGE",
]


def _normalize_type_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
                                   
    parts = [p.strip() for p in s.split(",")]
    return [p for p in parts if p]


def _looks_like_access_control(t: str) -> bool:
    s = (t or "").lower()
    s = s.replace("_", " ").replace("-", " ")
    return any(
        k in s
        for k in [
            "access control",
            "authorization",
            "authentication",
            "privilege",
            "onlyowner",
            "missing access control",
        ]
    )


def _map_types_to_8_buckets(raw_types):
\
\
\
       
    raw_types = _normalize_type_list(raw_types)
    swc_ids = []
    try:
        from src.tools.swc_mapper import map_types_to_swc_ids                                        

        swc_ids = map_types_to_swc_ids(raw_types)
    except Exception:
        swc_ids = []

    swc_set = set(_normalize_type_list(swc_ids))
    buckets = set()

    if "SWC-107" in swc_set:
        buckets.add("REENTRANCY")
    if "SWC-104" in swc_set:
        buckets.add("UNCHECKED_CALL")
    if "SWC-101" in swc_set:
        buckets.add("ARITHMETIC")
    if "SWC-120" in swc_set:
        buckets.add("BAD_RANDOMNESS")
    if "SWC-116" in swc_set:
        buckets.add("TIMESTAMP_DEPENDENCE")
    if "SWC-113" in swc_set or "SWC-126" in swc_set or "SWC-128" in swc_set:
        buckets.add("DOS")
    if "SWC-109" in swc_set or "SWC-124" in swc_set:
        buckets.add("STORAGE")

                                                    
    if any(_looks_like_access_control(t) for t in raw_types):
        buckets.add("ACCESS_CONTROL")

    return [b for b in BUCKET_ORDER if b in buckets]


def _bucket_primary(display_types) -> str:
\
\
\
\
       
    display_types = _normalize_type_list(display_types)
    bucket_hits = [t for t in BUCKET_ORDER if t in set(display_types)]
    if bucket_hits:
        return bucket_hits[0]
                                        
    mapped = _map_types_to_8_buckets(display_types)
    if mapped:
        return mapped[0]
    return "OTHER"


_TYPE_LINE_RE = re.compile(r"^\s*-\s*Type\s*:\s*(.+?)\s*$", re.IGNORECASE)


def extract_types_from_fix_prompt_input(prompt_input: str):
\
\
\
\
\
       
    if not prompt_input:
        return []
    types = []
    for line in str(prompt_input).splitlines():
        m = _TYPE_LINE_RE.match(line)
        if not m:
            continue
        raw = m.group(1).strip()
        if raw:
            types.extend([p.strip() for p in raw.split(",") if p.strip()])
    return types

def parse_ground_truth_code(output: str) -> str:
                        
    code_match = re.search(r'```(?:solidity)?\s*(.*?)\s*```', output, re.DOTALL)
    if code_match:
        return code_match.group(1).strip()
    return output.strip()

def extract_fix_id_from_sample_id(sample_id: str) -> int:
                                             
    match = re.search(r'fix_(\d+)', sample_id)
    if match:
        return int(match.group(1))
                   
    try:
        return int(sample_id)
    except ValueError:
        return None

def load_jsonl_test_samples(jsonl_path: str, limit: int = None):
                       
    print(f"正在加载测试集: {jsonl_path}")
    test_samples = []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                test_samples.append(json.loads(line))
    
    if limit:
        test_samples = test_samples[:limit]
    
    return test_samples


_EVAL_FIXER = None
_TEXT_SIM = None


def _init_eval_worker(fixer_config_kwargs: Dict[str, Any]):
\
\
\
\
       
    global _EVAL_FIXER
    from src.tools.llm_fixer import LLMFixer, FixerConfig

    cfg = FixerConfig(**fixer_config_kwargs)
    _EVAL_FIXER = LLMFixer(cfg)
                                                        
    global _TEXT_SIM
    try:
        from src.tools.code_similarity import text_similarity as _ts
    except Exception:
        _ts = None
    _TEXT_SIM = _ts


def _eval_one_sample(task: Dict[str, Any]) -> Dict[str, Any]:
\
\
       
    global _EVAL_FIXER, _TEXT_SIM
    if _EVAL_FIXER is None:
        raise RuntimeError("Worker fixer is not initialized. This should not happen.")

    func_data = task["func_data"]
    annotation = task["annotation"]
    n_samples = int(task["n_samples"])
    max_ir_change_rate = task.get("max_ir_change_rate")
    max_orig_sim = task.get("max_orig_sim")
    prompt_override = task.get("prompt_override")
    system_prompt_override = task.get("system_prompt_override")
    record_baseline = bool(task.get("record_baseline", False))
    baseline_only = bool(task.get("baseline_only", False))

    baseline_ver: Dict[str, Any] = {}
    if record_baseline or baseline_only:
        try:
            orig_code = str((func_data or {}).get("function_code") or "")
            if orig_code.strip():
                baseline_ver = _EVAL_FIXER.verify_fixed_code(func_data, orig_code)
        except Exception:
            baseline_ver = {}

                                                                                             
    if baseline_only:
        t0 = time.time()
        orig_code = str((func_data or {}).get("function_code") or "")
        is_ok = bool(baseline_ver.get("compiles")) and bool(baseline_ver.get("slither_passed"))
        if getattr(_EVAL_FIXER.config, "enable_mythril_check", False):
            is_ok = is_ok and bool(baseline_ver.get("mythril_passed", True))
        dt = float(time.time() - t0)
        result: Dict[str, Any] = {
            "sample_id": task.get("sample_id"),
            "contract": func_data.get("contract_path"),
            "function": func_data.get("function_name"),
            "total_generated": 1,
            "correct_generated": 1 if is_ok else 0,
            "best_candidate_code": (orig_code if is_ok else None),
            "passed_candidate_codes": ([orig_code] if is_ok else []),
            "best_candidate_ir_sim": float(baseline_ver.get("ir_sim", 0.0) or 0.0),
            "best_candidate_ir_change_rate": float(baseline_ver.get("ir_change_rate", 0.0) or 0.0),
            "passed_candidate_ir_sims": ([float(baseline_ver.get("ir_sim", 0.0) or 0.0)] if is_ok else []),
            "passed_candidate_ir_change_rates": ([float(baseline_ver.get("ir_change_rate", 0.0) or 0.0)] if is_ok else []),
            "best_candidate_orig_sim": 1.0 if is_ok else None,
            "passed_candidate_orig_sims": ([1.0] if is_ok else []),
            "sample_time_sec": dt,
            "sample_gen_time_sec": 0.0,
            "sample_verify_time_sec": dt,
            "llm_total_tokens": 0,
            "llm_prompt_tokens": 0,
            "llm_completion_tokens": 0,
            "llm_requests": 0,
            "rag": {"rag_used": False},
            "baseline_verification": baseline_ver,
        }
                                      
        jsonl_sample = task.get("jsonl_sample")
        parsed_types = []
        if isinstance(jsonl_sample, dict):
            parsed_types = extract_types_from_fix_prompt_input(jsonl_sample.get("input", ""))
        result_types = parsed_types
        if isinstance(annotation, dict):
            if not result_types:
                result_types = annotation.get("vulnerability_types", [])
            result["severity"] = annotation.get("severity")
            result["label"] = annotation.get("label")
        result["vulnerability_types"] = result_types
        result["vuln_bucket"] = _bucket_primary(result_types)
        if bool(task.get("include_source")):
            result["original_function_code"] = func_data.get("function_code")
            result["original_solidity_version"] = func_data.get("solidity_version")
                               
        gt_code = task.get("ground_truth_code")
        if gt_code:
            result["reference_code"] = gt_code
        return result

                                                                                        
    t0 = time.time()
    tok0 = int(_EVAL_FIXER.stats.get("total_tokens_used", 0) or 0)
    pt0 = int(_EVAL_FIXER.stats.get("prompt_tokens_used", 0) or 0)
    ct0 = int(_EVAL_FIXER.stats.get("completion_tokens_used", 0) or 0)
    req0 = int(_EVAL_FIXER.stats.get("total_requests", 0) or 0)

                                                                    
    gen_t0 = time.time()
    candidates = _EVAL_FIXER.generate_fix_candidates(
        func_data,
        annotation,
        n=n_samples,
        prompt_override=prompt_override,
        system_prompt_override=system_prompt_override,
        verify=False,
        sample_id=str(task.get("sample_id")) if task.get("sample_id") is not None else None,
    )
    gen_dt = float(time.time() - gen_t0)

                                                                             
    verify_dt = 0.0
    if isinstance(candidates, list) and candidates:
        for cand in candidates:
            fixed_code = (cand or {}).get("fixed_code")
            if not fixed_code:
                continue
            vt0 = time.time()
            try:
                cand["verification"] = _EVAL_FIXER.verify_fixed_code(func_data, fixed_code)
            finally:
                verify_dt += float(time.time() - vt0)

    dt = float(time.time() - t0)
    tok1 = int(_EVAL_FIXER.stats.get("total_tokens_used", 0) or 0)
    pt1 = int(_EVAL_FIXER.stats.get("prompt_tokens_used", 0) or 0)
    ct1 = int(_EVAL_FIXER.stats.get("completion_tokens_used", 0) or 0)
    req1 = int(_EVAL_FIXER.stats.get("total_requests", 0) or 0)

    correct_count = 0
    best_code = None
    passed_codes = []
    best_ir_sim = None
    best_ir_change_rate = None
    passed_ir_sims = []
    passed_ir_change_rates = []
    best_orig_sim = None
    passed_orig_sims = []
                                                                                            
    rag_meta_from_candidate: Dict[str, Any] = {}
    if candidates:
        rag_meta_from_candidate = candidates[0].get("rag", {}) or {}
    
    for cand in candidates:
        ver = cand.get("verification", {}) or {}
        is_correct = bool(ver.get("compiles")) and bool(ver.get("slither_passed"))
                                                                  
        if getattr(_EVAL_FIXER.config, "enable_mythril_check", False):
            is_correct = is_correct and bool(ver.get("mythril_passed", True))
                                                                                    
        orig_sim = None
        try:
            orig = str((func_data or {}).get("function_code") or "")
            cur = str(cand.get("fixed_code") or "")
            if orig and cur:
                if _TEXT_SIM is not None:
                    orig_sim = float(_TEXT_SIM(orig, cur))
                else:
                    orig_sim = float(difflib.SequenceMatcher(a=orig, b=cur).ratio())
        except Exception:
            orig_sim = None
        if max_orig_sim is not None:
            try:
                thr = float(max_orig_sim)
                if orig_sim is None:
                                                                                                        
                    is_correct = False
                else:
                    is_correct = is_correct and (float(orig_sim) < thr)
            except Exception:
                pass
                                                                                
        if max_ir_change_rate is not None:
            try:
                thr = float(max_ir_change_rate)
                                                                                         
                if not bool(ver.get("ir_available", False)):
                    is_correct = False
                else:
                    is_correct = is_correct and (float(ver.get("ir_change_rate", 0.0) or 0.0) <= thr)
            except Exception:
                                                                       
                pass
        if is_correct:
            correct_count += 1
            if len(passed_codes) < 3:
                passed_codes.append(cand.get("fixed_code"))
                passed_ir_sims.append(float(ver.get("ir_sim", 0.0) or 0.0))
                passed_ir_change_rates.append(float(ver.get("ir_change_rate", 0.0) or 0.0))
                if orig_sim is not None:
                    passed_orig_sims.append(float(orig_sim))
            if best_code is None:
                best_code = cand.get("fixed_code")
                best_ir_sim = float(ver.get("ir_sim", 0.0) or 0.0)
                best_ir_change_rate = float(ver.get("ir_change_rate", 0.0) or 0.0)
                best_orig_sim = float(orig_sim) if orig_sim is not None else None

    result: Dict[str, Any] = {
        "sample_id": task.get("sample_id"),
        "contract": func_data.get("contract_path"),
        "function": func_data.get("function_name"),
        "total_generated": n_samples,
        "correct_generated": correct_count,
        "best_candidate_code": best_code,
        "passed_candidate_codes": passed_codes,
        "best_candidate_ir_sim": best_ir_sim,
        "best_candidate_ir_change_rate": best_ir_change_rate,
        "passed_candidate_ir_sims": passed_ir_sims,
        "passed_candidate_ir_change_rates": passed_ir_change_rates,
        "best_candidate_orig_sim": best_orig_sim,
        "passed_candidate_orig_sims": passed_orig_sims,
        "sample_time_sec": dt,
        "sample_gen_time_sec": gen_dt,
        "sample_verify_time_sec": verify_dt,
        "llm_total_tokens": max(0, tok1 - tok0),
        "llm_prompt_tokens": max(0, pt1 - pt0),
        "llm_completion_tokens": max(0, ct1 - ct0),
        "llm_requests": max(0, req1 - req0),
        "rag": rag_meta_from_candidate,                                        
    }
    if record_baseline:
        result["baseline_verification"] = baseline_ver
                                                                                               
    if bool(task.get("include_source")):
        result["original_function_code"] = func_data.get("function_code")
        result["original_solidity_version"] = func_data.get("solidity_version")

                                  
    jsonl_sample = task.get("jsonl_sample")
    parsed_types = []
    if isinstance(jsonl_sample, dict):
        parsed_types = extract_types_from_fix_prompt_input(jsonl_sample.get("input", ""))
    result_types = parsed_types
    if isinstance(annotation, dict):
        if not result_types:
            result_types = annotation.get("vulnerability_types", [])
        result["severity"] = annotation.get("severity")
        result["label"] = annotation.get("label")

    result["vulnerability_types"] = result_types
    result["vuln_bucket"] = _bucket_primary(result_types)

                           
    gt_code = task.get("ground_truth_code")
    if gt_code:
        result["reference_code"] = gt_code

    return result


def run_evaluation(args: argparse.Namespace) -> dict:
                                                          
                                                                                                   
    from src.database.db_manager import DBManager
    from src.tools.llm_fixer import LLMFixer, FixerConfig

         
    baseline_only = bool(getattr(args, "baseline_only", False))
    api_key = args.api_key or os.getenv('OPENAI_API_KEY') or "empty"
    if (not baseline_only) and (not api_key or str(api_key).strip().lower() in {"none", ""}):
        raise ValueError("API Key required (pass --api-key or set OPENAI_API_KEY), unless --baseline-only is set")

    def _parse_csv_strs(value: Optional[str]) -> Optional[List[str]]:
        if value is None:
            return None
        s = str(value).strip()
        if not s:
            return None
        parts = [p.strip().lower() for p in s.split(",") if p.strip()]
        return parts or None

    config = FixerConfig(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
        temperature=args.temperature,
        top_p=args.top_p,
        max_tokens=args.max_tokens,
        seed=args.seed,
        verbose=args.verbose,
        print_llm_responses=bool(getattr(args, "print_llm_responses", False)),
        llm_responses_out=getattr(args, "llm_responses_out", None),
        reasoning_effort=getattr(args, "reasoning_effort", None),
        max_output_tokens=getattr(args, "max_output_tokens", None),
        force_single_n=bool(getattr(args, "force_single_n", False)),
        llm_request_workers=int(getattr(args, "llm_request_workers", 1) or 1),
        enable_compilation_check=True,            
        enable_slither_check=True,
        enable_mythril_check=bool(getattr(args, "enable_mythril_check", False)),
        mythril_timeout=int(getattr(args, "mythril_timeout", 120) or 120),
        mythril_severities=_parse_csv_strs(getattr(args, "mythril_severities", None)),
        mythril_bin=str(getattr(args, "mythril_bin", "myth") or "myth"),
        evaluation_mode=True,          
        strict_verification=bool(getattr(args, "strict_verification", False)),
        mythril_uncertain_as_pass=bool(getattr(args, "mythril_uncertain_as_pass", True)),
                        
        rag_mode=str(getattr(args, "rag_mode", "off") or "off"),
        rag_index_path=getattr(args, "rag_index_path", None),
        rag_build_from_jsonl=getattr(args, "rag_build_from_jsonl", None),
        rag_build_limit=int(getattr(args, "rag_build_limit", 5000) or 5000),
        rag_top_k=int(getattr(args, "rag_top_k", 3) or 3),
        rag_max_demos=int(getattr(args, "rag_max_demos", 3) or 3),
        rag_max_chars_each=int(getattr(args, "rag_max_chars_each", 800) or 800),
        rag_max_added_tokens=getattr(args, "rag_max_added_tokens", None),
        rag_mmr_lambda=float(getattr(args, "rag_mmr_lambda", 0.7) or 0.7),
        rag_fusion_weights=str(getattr(args, "rag_fusion_weights", "0.35,0.35,0.2,0.1") or "0.35,0.35,0.2,0.1"),
    )
    
    fixer = LLMFixer(config)
    db_manager = DBManager(args.db_path)
    
          
    print("正在加载数据...")
    session = db_manager.get_session()
    from src.database.models import SmartContractFunction
    
                               
    if args.jsonl_path:
                       
        test_samples = load_jsonl_test_samples(args.jsonl_path, args.limit)
        print(f"评估数据集大小: {len(test_samples)} (从JSONL加载)")
        
        use_jsonl_prompt = bool(getattr(args, "use_jsonl_prompt", False))

                                                  
        eval_data = []

                         
        sample_infos = []
        fix_ids = []
        for sample in test_samples:
            sample_id = sample.get('id', 'unknown')
            fix_id = extract_fix_id_from_sample_id(sample_id)
            if fix_id is None:
                print(f"警告: 无法从样本ID '{sample_id}' 提取fix_id，跳过")
                continue
            sample_infos.append((sample_id, fix_id, sample))
            fix_ids.append(fix_id)

                      
        funcs = session.query(SmartContractFunction).filter(SmartContractFunction.id.in_(list(set(fix_ids)))).all()
        func_by_id = {f.id: f for f in funcs}

                         
        for sample_id, fix_id, sample in sample_infos:
            func = func_by_id.get(fix_id)
            if func is None:
                print(f"警告: 在数据库中未找到fix_id={fix_id}的函数，跳过")
                continue

                                                                    
                                                                                                             
                                                                                                                                         
            if func.llm_audit is None and not use_jsonl_prompt:
                print(f"警告: fix_id={fix_id} 在数据库中 llm_audit 为空，且未启用 --use-jsonl-prompt，跳过该样本")
                continue

            ground_truth = sample.get('output', '')
            gt_code = parse_ground_truth_code(ground_truth)

            prompt_override = None
            system_prompt_override = None
            if use_jsonl_prompt:
                                                                 
                prompt_override = sample.get("input")
                system_prompt_override = sample.get("instruction")

            eval_data.append(
                {
                    'func': func,
                    'sample_id': sample_id,
                    'ground_truth_code': gt_code,
                    'jsonl_sample': sample,
                    'prompt_override': prompt_override,
                    'system_prompt_override': system_prompt_override,
                }
            )
        
        print(f"成功加载 {len(eval_data)} 个样本（关联数据库后）")
    else:
                       
        query = session.query(SmartContractFunction).filter(
            SmartContractFunction.llm_audit.isnot(None)
        )
        
        all_funcs = query.all()
        vulnerable_funcs = [
            f for f in all_funcs 
            if f.llm_audit and f.llm_audit.get('label') == 'vulnerable'
        ]
        
        if args.limit:
            vulnerable_funcs = vulnerable_funcs[:args.limit]
        
        print(f"评估数据集大小: {len(vulnerable_funcs)} (从数据库加载)")
        
        eval_data = [{'func': f, 'sample_id': f.id, 'ground_truth_code': None, 'jsonl_sample': None} 
                    for f in vulnerable_funcs]

                                                                                                           
    tasks: List[Dict[str, Any]] = []
    for data_item in eval_data:
        func = data_item["func"]
        func_data = {
            "function_name": func.function_name,
            "function_code": func.function_code,
            "solidity_version": func.solidity_version,
            "contract_context": func.contract_context,
            "contract_path": func.contract_path,
        }
        tasks.append(
            {
                "sample_id": data_item["sample_id"],
                "func_data": func_data,
                "annotation": func.llm_audit,
                "ground_truth_code": data_item.get("ground_truth_code"),
                "jsonl_sample": data_item.get("jsonl_sample"),
                "n_samples": int(args.n_samples),
                "max_ir_change_rate": getattr(args, "max_ir_change_rate", None),
                "max_orig_sim": getattr(args, "max_orig_sim", None),
                "prompt_override": data_item.get("prompt_override"),
                "system_prompt_override": data_item.get("system_prompt_override"),
                "include_source": bool(getattr(args, "include_source", False)),
                "record_baseline": bool(getattr(args, "record_baseline", False)),
                "baseline_only": bool(getattr(args, "baseline_only", False)),
            }
        )

    eval_results: List[Dict[str, Any]] = []
    run_t0 = time.time()

                
    disable_tqdm = str(os.getenv("TQDM_DISABLE", "")).strip().lower() in {"1", "true", "yes"}
    sample_workers = max(1, int(getattr(args, "sample_workers", 1) or 1))
    sample_executor = str(getattr(args, "sample_executor", "process") or "process").lower()
    if sample_executor not in {"thread", "process"}:
        sample_executor = "process"

                                                                                                                      
                                                                         
    if sample_workers > 1 and sample_executor == "thread":
        print("⚠️  sample_executor=thread is unsafe with compilation/slither checks enabled; switching to process.")
        sample_executor = "process"

    if sample_workers <= 1 or not tasks:
                                                                                       
        for task in tqdm(tasks, desc="Evaluating", disable=disable_tqdm):
                                                                     
                                                   
            func_data = task["func_data"]
            annotation = task["annotation"]
            jsonl_sample = task.get("jsonl_sample")
            record_baseline = bool(getattr(args, "record_baseline", False))
            baseline_only = bool(getattr(args, "baseline_only", False))

            baseline_ver: Dict[str, Any] = {}
            if record_baseline or baseline_only:
                try:
                    orig_code = str((func_data or {}).get("function_code") or "")
                    if orig_code.strip():
                        baseline_ver = fixer.verify_fixed_code(func_data, orig_code)
                except Exception:
                    baseline_ver = {}

            if baseline_only:
                t0b = time.time()
                orig_code = str((func_data or {}).get("function_code") or "")
                is_ok = bool(baseline_ver.get("compiles")) and bool(baseline_ver.get("slither_passed"))
                if getattr(config, "enable_mythril_check", False):
                    is_ok = is_ok and bool(baseline_ver.get("mythril_passed", True))
                dtb = float(time.time() - t0b)
                result: Dict[str, Any] = {
                    "sample_id": task.get("sample_id"),
                    "contract": func_data.get("contract_path"),
                    "function": func_data.get("function_name"),
                    "total_generated": 1,
                    "correct_generated": 1 if is_ok else 0,
                    "best_candidate_code": (orig_code if is_ok else None),
                    "passed_candidate_codes": ([orig_code] if is_ok else []),
                    "best_candidate_ir_sim": float(baseline_ver.get("ir_sim", 0.0) or 0.0),
                    "best_candidate_ir_change_rate": float(baseline_ver.get("ir_change_rate", 0.0) or 0.0),
                    "passed_candidate_ir_sims": ([float(baseline_ver.get("ir_sim", 0.0) or 0.0)] if is_ok else []),
                    "passed_candidate_ir_change_rates": ([float(baseline_ver.get("ir_change_rate", 0.0) or 0.0)] if is_ok else []),
                    "sample_time_sec": dtb,
                    "sample_gen_time_sec": 0.0,
                    "sample_verify_time_sec": dtb,
                    "llm_total_tokens": 0,
                    "llm_prompt_tokens": 0,
                    "llm_completion_tokens": 0,
                    "llm_requests": 0,
                    "rag": {"rag_used": False},
                    "baseline_verification": baseline_ver,
                }
                parsed_types = []
                if isinstance(jsonl_sample, dict):
                    parsed_types = extract_types_from_fix_prompt_input(jsonl_sample.get("input", ""))
                result_types = parsed_types
                if isinstance(annotation, dict):
                    if not result_types:
                        result_types = annotation.get("vulnerability_types", [])
                    result["severity"] = annotation.get("severity")
                    result["label"] = annotation.get("label")
                result["vulnerability_types"] = result_types
                result["vuln_bucket"] = _bucket_primary(result_types)
                if bool(getattr(args, "include_source", False)):
                    result["original_function_code"] = func_data.get("function_code")
                    result["original_solidity_version"] = func_data.get("solidity_version")
                if task.get("ground_truth_code"):
                    result["reference_code"] = task.get("ground_truth_code")
                eval_results.append(result)
                continue

                                                                                            
            t0 = time.time()
            tok0 = int(fixer.stats.get("total_tokens_used", 0) or 0)
            pt0 = int(fixer.stats.get("prompt_tokens_used", 0) or 0)
            ct0 = int(fixer.stats.get("completion_tokens_used", 0) or 0)
            req0 = int(fixer.stats.get("total_requests", 0) or 0)

                                                                            
            gen_t0 = time.time()
            candidates = fixer.generate_fix_candidates(
                func_data,
                annotation,
                n=args.n_samples,
                prompt_override=task.get("prompt_override"),
                system_prompt_override=task.get("system_prompt_override"),
                verify=False,
                sample_id=str(task.get("sample_id")) if task.get("sample_id") is not None else None,
            )
            gen_dt = float(time.time() - gen_t0)

                                                                                     
            verify_dt = 0.0
            if isinstance(candidates, list) and candidates:
                for cand in candidates:
                    fixed_code = (cand or {}).get("fixed_code")
                    if not fixed_code:
                        continue
                    vt0 = time.time()
                    try:
                        cand["verification"] = fixer.verify_fixed_code(func_data, fixed_code)
                    finally:
                        verify_dt += float(time.time() - vt0)

            dt = float(time.time() - t0)
            tok1 = int(fixer.stats.get("total_tokens_used", 0) or 0)
            pt1 = int(fixer.stats.get("prompt_tokens_used", 0) or 0)
            ct1 = int(fixer.stats.get("completion_tokens_used", 0) or 0)
            req1 = int(fixer.stats.get("total_requests", 0) or 0)
            correct_count = 0
            best_code = None
            passed_codes = []
            best_ir_sim = None
            best_ir_change_rate = None
            passed_ir_sims = []
            passed_ir_change_rates = []
                                                                                                    
            rag_meta_from_candidate: Dict[str, Any] = {}
            if candidates:
                rag_meta_from_candidate = candidates[0].get("rag", {}) or {}
            
            for cand in candidates:
                ver = cand.get("verification", {}) or {}
                is_correct = bool(ver.get("compiles")) and bool(ver.get("slither_passed"))
                if getattr(config, "enable_mythril_check", False):
                    is_correct = is_correct and bool(ver.get("mythril_passed", True))
                                                                                        
                if getattr(args, "max_ir_change_rate", None) is not None:
                    try:
                        thr = float(getattr(args, "max_ir_change_rate"))
                        if not bool(ver.get("ir_available", False)):
                            is_correct = False
                        else:
                            is_correct = is_correct and (float(ver.get("ir_change_rate", 0.0) or 0.0) <= thr)
                    except Exception:
                        pass
                if is_correct:
                    correct_count += 1
                    if len(passed_codes) < 3:
                        passed_codes.append(cand.get("fixed_code"))
                        passed_ir_sims.append(float(ver.get("ir_sim", 0.0) or 0.0))
                        passed_ir_change_rates.append(float(ver.get("ir_change_rate", 0.0) or 0.0))
                    if best_code is None:
                        best_code = cand.get("fixed_code")
                        best_ir_sim = float(ver.get("ir_sim", 0.0) or 0.0)
                        best_ir_change_rate = float(ver.get("ir_change_rate", 0.0) or 0.0)

            result: Dict[str, Any] = {
                "sample_id": task.get("sample_id"),
                "contract": func_data.get("contract_path"),
                "function": func_data.get("function_name"),
                "total_generated": int(args.n_samples),
                "correct_generated": correct_count,
                "best_candidate_code": best_code,
                "passed_candidate_codes": passed_codes,
                "best_candidate_ir_sim": best_ir_sim,
                "best_candidate_ir_change_rate": best_ir_change_rate,
                "passed_candidate_ir_sims": passed_ir_sims,
                "passed_candidate_ir_change_rates": passed_ir_change_rates,
                "sample_time_sec": dt,
                "sample_gen_time_sec": gen_dt,
                "sample_verify_time_sec": verify_dt,
                "llm_total_tokens": max(0, tok1 - tok0),
                "llm_prompt_tokens": max(0, pt1 - pt0),
                "llm_completion_tokens": max(0, ct1 - ct0),
                "llm_requests": max(0, req1 - req0),
                "rag": rag_meta_from_candidate,                                        
            }
            if record_baseline:
                result["baseline_verification"] = baseline_ver
            if bool(getattr(args, "include_source", False)):
                result["original_function_code"] = func_data.get("function_code")
                result["original_solidity_version"] = func_data.get("solidity_version")

            parsed_types = []
            if isinstance(jsonl_sample, dict):
                parsed_types = extract_types_from_fix_prompt_input(jsonl_sample.get("input", ""))
            result_types = parsed_types
            if isinstance(annotation, dict):
                if not result_types:
                    result_types = annotation.get("vulnerability_types", [])
                result["severity"] = annotation.get("severity")
                result["label"] = annotation.get("label")
            result["vulnerability_types"] = result_types
            result["vuln_bucket"] = _bucket_primary(result_types)

            if task.get("ground_truth_code"):
                result["reference_code"] = task.get("ground_truth_code")

            eval_results.append(result)
    else:
                                                           
        Executor = ThreadPoolExecutor if sample_executor == "thread" else ProcessPoolExecutor
        fixer_cfg_kwargs = {
            "api_key": config.api_key,
            "base_url": config.base_url,
            "model": config.model,
            "temperature": config.temperature,
            "top_p": config.top_p,
            "max_tokens": config.max_tokens,
            "seed": config.seed,
            "verbose": False,                              
            "print_llm_responses": bool(getattr(args, "print_llm_responses", False)),
            "llm_responses_out": getattr(args, "llm_responses_out", None),
            "llm_responses_append_pid": True,
            "reasoning_effort": getattr(args, "reasoning_effort", None),
            "max_output_tokens": getattr(args, "max_output_tokens", None),
            "force_single_n": bool(getattr(config, "force_single_n", False)),
            "llm_request_workers": int(getattr(config, "llm_request_workers", 1) or 1),
            "enable_compilation_check": config.enable_compilation_check,
            "enable_slither_check": config.enable_slither_check,
            "enable_mythril_check": config.enable_mythril_check,
            "evaluation_mode": config.evaluation_mode,
            "timeout": config.timeout,
            "max_retries": config.max_retries,
            "retry_delay": config.retry_delay,
            "presence_penalty": config.presence_penalty,
            "frequency_penalty": config.frequency_penalty,
            "use_rich_fix_prompt": config.use_rich_fix_prompt,
            "enable_error_feedback": config.enable_error_feedback,
            "max_error_lines": config.max_error_lines,
            "mythril_timeout": config.mythril_timeout,
            "mythril_severities": config.mythril_severities,
            "mythril_bin": config.mythril_bin,
            "strict_verification": bool(getattr(config, "strict_verification", False)),
                                                      
            "rag_mode": str(getattr(config, "rag_mode", "off") or "off"),
            "rag_index_path": getattr(config, "rag_index_path", None),
            "rag_build_from_jsonl": getattr(config, "rag_build_from_jsonl", None),
            "rag_build_limit": int(getattr(config, "rag_build_limit", 5000) or 5000),
            "rag_top_k": int(getattr(config, "rag_top_k", 3) or 3),
            "rag_max_demos": int(getattr(config, "rag_max_demos", 3) or 3),
            "rag_max_chars_each": int(getattr(config, "rag_max_chars_each", 800) or 800),
            "rag_max_added_tokens": getattr(config, "rag_max_added_tokens", None),
            "rag_mmr_lambda": float(getattr(config, "rag_mmr_lambda", 0.7) or 0.7),
            "rag_fusion_weights": str(getattr(config, "rag_fusion_weights", "0.35,0.35,0.2,0.1") or "0.35,0.35,0.2,0.1"),
        }

        failures: List[Dict[str, Any]] = []
        with Executor(
            max_workers=sample_workers,
            initializer=_init_eval_worker,
            initargs=(fixer_cfg_kwargs,),
        ) as ex:
            future_to_task: Dict[Future, Dict[str, Any]] = {}
            for task in tasks:
                future_to_task[ex.submit(_eval_one_sample, task)] = task

            it = as_completed(future_to_task)
            if not disable_tqdm:
                it = tqdm(it, total=len(future_to_task), desc=f"Evaluating (parallel x{sample_workers})")

            for fut in it:
                task = future_to_task[fut]
                try:
                    eval_results.append(fut.result())
                except Exception as e:
                    failures.append(
                        {
                            "sample_id": task.get("sample_id"),
                            "error": repr(e),
                            "traceback": traceback.format_exc(),
                        }
                    )
        if failures:
            print(f"⚠️  {len(failures)} samples failed during evaluation. Showing first 3:")
            for f in failures[:3]:
                print(f" - sample_id={f.get('sample_id')}, error={f.get('error')}")
    
          
    k_values = [1, 5, 10] if args.n_samples >= 10 else [1, args.n_samples]
    metrics = compute_metrics(eval_results, k_values=k_values)

                                                                                                           
    run_wall_time_sec = float(time.time() - run_t0)
    total_sample_time = sum(float(r.get("sample_time_sec", 0.0) or 0.0) for r in eval_results)
    total_sample_gen_time = sum(float(r.get("sample_gen_time_sec", 0.0) or 0.0) for r in eval_results)
    total_sample_verify_time = sum(float(r.get("sample_verify_time_sec", 0.0) or 0.0) for r in eval_results)
    total_tokens = sum(int(r.get("llm_total_tokens", 0) or 0) for r in eval_results)
    total_prompt_tokens = sum(int(r.get("llm_prompt_tokens", 0) or 0) for r in eval_results)
    total_completion_tokens = sum(int(r.get("llm_completion_tokens", 0) or 0) for r in eval_results)
    total_requests = sum(int(r.get("llm_requests", 0) or 0) for r in eval_results)
    n_samples_eval = len(eval_results) or 1

    metrics["run_wall_time_sec"] = run_wall_time_sec
    metrics["sample_time_sec_avg"] = (total_sample_time / n_samples_eval) if n_samples_eval else 0.0
    metrics["sample_gen_time_sec_avg"] = (total_sample_gen_time / n_samples_eval) if n_samples_eval else 0.0
    metrics["sample_verify_time_sec_avg"] = (total_sample_verify_time / n_samples_eval) if n_samples_eval else 0.0
    metrics["llm_total_tokens"] = float(total_tokens)
    metrics["llm_prompt_tokens"] = float(total_prompt_tokens)
    metrics["llm_completion_tokens"] = float(total_completion_tokens)
    metrics["llm_requests"] = float(total_requests)
    metrics["llm_tokens_per_sample"] = float(total_tokens / n_samples_eval) if n_samples_eval else 0.0

                                                                                                        
    ir_sims: List[float] = []
    ir_change_rates: List[float] = []
    highest_ir_sims: List[float] = []
    lowest_ir_change_rates: List[float] = []
    for r in eval_results:
        bs = r.get("best_candidate_ir_sim")
        bc = r.get("best_candidate_ir_change_rate")
        if isinstance(bs, (int, float)):
            ir_sims.append(float(bs))
        if isinstance(bc, (int, float)):
            ir_change_rates.append(float(bc))
        sims = r.get("passed_candidate_ir_sims")
        crs = r.get("passed_candidate_ir_change_rates")
        if isinstance(sims, list) and sims:
            try:
                highest_ir_sims.append(max(float(x) for x in sims))
            except Exception:
                pass
        if isinstance(crs, list) and crs:
            try:
                lowest_ir_change_rates.append(min(float(x) for x in crs))
            except Exception:
                pass

    if ir_sims:
        metrics["ir_sim"] = sum(ir_sims) / len(ir_sims)
    if ir_change_rates:
        metrics["ir_change_rate"] = sum(ir_change_rates) / len(ir_change_rates)
    if highest_ir_sims:
        metrics["highest_ir_sim"] = sum(highest_ir_sims) / len(highest_ir_sims)
    if lowest_ir_change_rates:
        metrics["lowest_ir_change_rate"] = sum(lowest_ir_change_rates) / len(lowest_ir_change_rates)

                                                          
    bucket_total = {k: 0 for k in BUCKET_ORDER + ["OTHER"]}
    bucket_solved = {k: 0 for k in BUCKET_ORDER + ["OTHER"]}
    bucket_pass = {b: {k: [] for k in k_values} for b in BUCKET_ORDER + ["OTHER"]}
    for r in eval_results:
        b = r.get("vuln_bucket") or "OTHER"
        if b not in bucket_total:
            b = "OTHER"
        bucket_total[b] += 1
        if r.get("correct_generated", 0) > 0:
            bucket_solved[b] += 1
                                                                                             
        n = int(r.get("total_generated", 0) or 0)
        c = int(r.get("correct_generated", 0) or 0)
        for k in k_values:
            if n >= k:
                bucket_pass[b][k].append(calculate_pass_at_k(n, c, k))

    for b in BUCKET_ORDER + ["OTHER"]:
        n = bucket_total[b]
        metrics[f"type_n_{b}"] = n
        metrics[f"solved_rate_{b}"] = (bucket_solved[b] / n) if n else 0.0
        for k in k_values:
            vals = bucket_pass[b][k]
            metrics[f"pass@{k}_{b}"] = (sum(vals) / len(vals)) if vals else 0.0
    
    print("\n" + "="*60)
    print("评估结果:")
    print(f"模型: {args.model}")
    print(f"数据源: {'JSONL测试集' if args.jsonl_path else '数据库'}")
    if args.jsonl_path:
        print(f"JSONL路径: {args.jsonl_path}")
    print(f"样本数: {len(eval_results)}")
    print(f"N (每个样本生成数): {args.n_samples}")
    print(f"temperature={args.temperature}, top_p={args.top_p}, seed={args.seed}")
    print("-" * 60)
    print(f"Solved Rate (VRR): {metrics['solved_rate']:.2%}")
                                                     
    for b in BUCKET_ORDER + ["OTHER"]:
        n = int(metrics.get(f"type_n_{b}", 0))
        if n > 0:
            print(f"Solved Rate [{b}] (n={n}): {metrics.get(f'solved_rate_{b}', 0.0):.2%}")
            for k in k_values:
                print(f"Pass@{k} [{b}]: {metrics.get(f'pass@{k}_{b}', 0.0):.2%}")
    for k, v in metrics.items():
        if k.startswith('pass@'):
            print(f"{k}: {v:.2%}")
    if 'bleu' in metrics:
        print(f"BLEU: {metrics['bleu']:.4f}")
    print("="*60)
    
    return {
        'meta': vars(args),
        'metrics': metrics,
        'details': eval_results
    }

def main():
    parser = argparse.ArgumentParser(description='评估修复模型性能 (Pass@k, VRR)')
    parser.add_argument('--db-path', default='sqlite:///smart_contracts.db', help='数据库路径')
    parser.add_argument('--jsonl-path', type=str, default=None, help='JSONL测试集路径 (可选，如指定则从JSONL加载)')
    parser.add_argument('--limit', type=int, default=None, help='评估样本数量')
    parser.add_argument('--n-samples', type=int, default=5, help='每个样本生成的候选数 (n)')
    parser.add_argument('--model', type=str, default='deepseek-chat', help='模型名称')
    parser.add_argument('--api-key', type=str, default='None', help='API Key (默认读取 OPENAI_API_KEY)')
    parser.add_argument('--base-url', type=str, default='http://localhost:8000/v1', help='API Base URL')
    parser.add_argument('--output', type=str, default='evaluation_results.json', help='结果保存路径')
    parser.add_argument('--temperature', type=float, default=0.7, help='采样温度 (影响多样性/Pass@k)')
    parser.add_argument('--top-p', type=float, default=None, help='Top-p (nucleus sampling)')
    parser.add_argument('--max-tokens', type=int, default=None, help='生成最大 token 数')
    parser.add_argument('--seed', type=int, default=None, help='采样随机种子 (后端需支持，如 vLLM)')
    parser.add_argument('--verbose', action='store_true', help='输出更详细日志（建议小规模调试时使用）')
    parser.add_argument(
        "--print-llm-responses",
        action="store_true",
        help="仅打印每次生成的 LLM 原始完整回复到控制台（不需要开启 --verbose；并行时输出可能交错）",
    )
    parser.add_argument(
        "--llm-responses-out",
        type=str,
        default=None,
        help="可选：将每个 sample 的每个 candidate 的 LLM 原始完整回复追加写入 JSONL 文件（并行时会自动按 pid 分文件以避免冲突）",
    )
    parser.add_argument(
        "--reasoning-effort",
        type=str,
        default=None,
        choices=["minimal", "low", "medium", "high"],
        help="可选：降低/限制模型隐藏思考强度（需网关/模型支持；不支持会自动移除该参数重试）",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help="可选：限制输出总 token（含隐藏思考，需网关/模型支持；不支持会自动移除该参数重试）",
    )
    parser.add_argument(
        '--force-single-n',
        action='store_true',
        help='强制将 n-samples 拆成循环 n 次 (每次请求 n=1)，用于可控对比实验（忽略模型/provider 是否支持 n>1）',
    )
    parser.add_argument(
        '--llm-request-workers',
        type=int,
        default=1,
        help='当走“循环 n 次（每次 n=1）”时，用多少线程并发发送 LLM 请求（仅生成阶段；默认 1=串行）',
    )
    parser.add_argument(
        '--max-ir-change-rate',
        type=float,
        default=None,
        help='可选：IR 变化率上限阈值。若候选 ir_change_rate > 阈值，则即使验证通过也按失败处理（例如 0.5）。',
    )
    parser.add_argument(
        '--max-orig-sim',
        type=float,
        default=None,
        help='可选：与原始函数代码的文本相似度上限阈值。若 similarity >= 阈值，则即使验证通过也按失败处理（用于抑制“原样输出/几乎不改”）。例如 0.995。',
    )
    parser.add_argument('--sample-workers', type=int, default=1, help='单次评估(run)内部的样本并行 worker 数（默认串行）')
    parser.add_argument(
        '--sample-executor',
        type=str,
        default='process',
        choices=['thread', 'process'],
        help='run 内部并行执行器：process(默认，隔离 env/solc 更安全) 或 thread',
    )
    parser.add_argument(
        "--use-jsonl-prompt",
        action="store_true",
        help="当指定 --jsonl-path 时：使用 JSONL 的 instruction/input 作为真实提示词生成（不从 DB 重新构建 prompt）；DB 仍用于验证（编译/Slither）",
    )
    parser.add_argument("--enable-mythril-check", action="store_true", help="启用 Mythril 验证（评估时会纳入成功判定）")
    parser.add_argument("--mythril-timeout", type=int, default=120, help="Mythril 单样本超时(秒)")
    parser.add_argument(
        "--mythril-severities",
        type=str,
        default=None,
        help="逗号分隔的 Mythril 严重级别过滤，例如: high,medium；为空则使用默认(high,medium)",
    )
    parser.add_argument("--mythril-bin", type=str, default="myth", help="Mythril 可执行文件名/路径（默认 myth）")
    parser.add_argument(
        "--strict-verification",
        action="store_true",
        help="严格验证模式：编译/Slither/Mythril 任意异常都视为失败（fail-closed），避免通过率被工具失效虚高",
    )
    parser.add_argument(
        "--mythril-uncertain-as-pass",
        action="store_true",
        default=True,
        help="Mythril 超时/不可用/非0退出码/解析失败等不确定情况仍视为通过（默认开启；仅在 --enable-mythril-check 时生效）",
    )
    parser.add_argument(
        "--mythril-uncertain-as-fail",
        action="store_false",
        dest="mythril_uncertain_as_pass",
        help="将 Mythril 的超时/不可用等不确定情况视为失败（更严格、更慢、更容易受环境影响）。",
    )
    parser.add_argument(
        "--include-source",
        action="store_true",
        help="在 details 中附带 original_function_code/original_solidity_version，便于人工审查（会显著增大输出文件）",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help="可选：在评测时额外对“原始函数代码”跑一遍验证(compile/slither/mythril)，并写入 details[*].baseline_verification 便于诊断“工具是否能检出原始漏洞”。",
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="仅跑 baseline：不调用LLM、不生成候选；对每个样本仅验证原始函数代码，并将其作为唯一候选写入结果（用于诊断数据集可检测性）。",
    )

                                   
                                                                 
                                   
    parser.add_argument(
        "--rag-mode",
        type=str,
        default="off",
        choices=["off", "always"],
        help="RAG usage mode during evaluation: off=disable; always=prepend retrieved demos before the user prompt.",
    )
    parser.add_argument("--rag-index-path", type=str, default=None, help="Path to a saved RAG index dir (HybridRetriever.save/load).")
    parser.add_argument(
        "--rag-build-from-jsonl",
        type=str,
        default=None,
        help="If set (or if rag-index-path missing), build RAG corpus from this fix_sft jsonl.",
    )
    parser.add_argument("--rag-build-limit", type=int, default=5000, help="Max docs to build RAG index from jsonl.")
    parser.add_argument("--rag-top-k", type=int, default=3, help="How many retrieval results to use.")
    parser.add_argument("--rag-max-demos", type=int, default=3, help="How many demos to inject into the prompt.")
    parser.add_argument("--rag-max-chars-each", type=int, default=800, help="Max chars per demo code snippet.")
    parser.add_argument(
        "--rag-max-added-tokens",
        type=int,
        default=None,
        help="Max tokens added by RAG demos (best-effort; no mid-snippet truncation; demos are compacted or dropped).",
    )
    parser.add_argument("--rag-mmr-lambda", type=float, default=0.7, help="MMR lambda for demo diversity.")
    parser.add_argument("--rag-fusion-weights", type=str, default="0.35,0.35,0.2,0.1", help="Weights token,bm25,dense,struct.")
    
    args = parser.parse_args()
    output_data = run_evaluation(args)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f"详细结果已保存至: {args.output}")

if __name__ == "__main__":
    main()

