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
   

import sys
import os
import json
import argparse
import math
import time
import traceback
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Future, as_completed

                                                                       
try:
    from tqdm.auto import tqdm                
except Exception:                    
    tqdm = None                

            
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from scripts.evaluate_fixes import run_evaluation              
from scripts.evaluate_fixes import BUCKET_ORDER              
from src.evaluation.metrics import calculate_bleu, calculate_edit_similarity              


def _parse_csv_floats(value: str) -> List[float]:
    return [float(x.strip()) for x in value.split(",") if x.strip() != ""]


def _parse_csv_ints(value: str) -> List[int]:
    return [int(x.strip()) for x in value.split(",") if x.strip() != ""]


def _parse_top_ps(value: str) -> List[Optional[float]]:
\
\
\
\
\
       
    out: List[Optional[float]] = []
    for item in value.split(","):
        s = item.strip().lower()
        if not s:
            continue
        if s in {"none", "null"}:
            out.append(None)
        else:
            out.append(float(s))
    return out


def _mean_std(values: List[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    if len(values) == 1:
        return mean, 0.0
    var = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return mean, math.sqrt(var)

def _safe_print(msg: str) -> None:
\
\
\
       
    if tqdm is not None:
        try:
            tqdm.write(str(msg))
            return
        except Exception:
            pass
    print(msg, flush=True)

def _norm_optional_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().lower()
    if s in {"none", "null", ""}:
        return None
    return float(s)


def _run_key(
    *,
    model: str,
    n_samples: int,
    temperature: float,
    top_p: Optional[float],
    seed: int,
    jsonl_path: Optional[str],
    limit: Optional[int],
    base_url: str,
    use_jsonl_prompt: bool,
    enable_mythril_check: bool,
    mythril_timeout: Optional[int],
    mythril_severities: Optional[str],
    mythril_bin: Optional[str],
    force_single_n: bool,
    llm_request_workers: int,
    max_ir_change_rate: Optional[float],
    max_orig_sim: Optional[float],
    engine: str,
    sguard_dir: Optional[str],
    sguard_use_simplified_contract: bool,
    rag_mode: str,
    rag_index_path: Optional[str],
    rag_build_from_jsonl: Optional[str],
    rag_build_limit: Optional[int],
    rag_top_k: Optional[int],
    rag_max_demos: Optional[int],
    rag_max_chars_each: Optional[int],
    rag_max_added_tokens: Optional[int],
    rag_mmr_lambda: Optional[float],
    rag_fusion_weights: Optional[str],
) -> Tuple[Any, ...]:
                        
    return (
        model,
        int(n_samples),
        float(temperature),
        _norm_optional_float(top_p),
        int(seed),
        jsonl_path or "",
        int(limit) if limit is not None else None,
        base_url,
        bool(use_jsonl_prompt),
        bool(enable_mythril_check),
        int(mythril_timeout) if mythril_timeout is not None else None,
        (str(mythril_severities).strip().lower() if mythril_severities is not None else ""),
        str(mythril_bin or ""),
        bool(force_single_n),
        int(llm_request_workers),
        _norm_optional_float(max_ir_change_rate),
        _norm_optional_float(max_orig_sim),
        str(engine or "llm").strip().lower(),
        str(sguard_dir or ""),
        bool(sguard_use_simplified_contract),
        str(rag_mode or "off").strip().lower(),
        str(rag_index_path or ""),
        str(rag_build_from_jsonl or ""),
        int(rag_build_limit) if rag_build_limit is not None else None,
        int(rag_top_k) if rag_top_k is not None else None,
        int(rag_max_demos) if rag_max_demos is not None else None,
        int(rag_max_chars_each) if rag_max_chars_each is not None else None,
        int(rag_max_added_tokens) if rag_max_added_tokens is not None else None,
        _norm_optional_float(rag_mmr_lambda),
        str(rag_fusion_weights or ""),
    )

def _compute_highest_bleu_from_details(details: Any) -> float:
\
\
\
\
\
       
    if not isinstance(details, list) or not details:
        return 0.0
    per_sample_max: List[float] = []
    for r in details:
        if not isinstance(r, dict):
            continue
        ref = r.get("reference_code")
        passed = r.get("passed_candidate_codes")
        if not ref or not isinstance(ref, str):
            continue
        if not isinstance(passed, list) or not passed:
            continue
        scores: List[float] = []
        for cand in passed:
            if not cand or not isinstance(cand, str):
                continue
            try:
                scores.append(float(calculate_bleu(ref, cand)))
            except Exception:
                continue
        if scores:
            per_sample_max.append(max(scores))
    if not per_sample_max:
        return 0.0
    return sum(per_sample_max) / len(per_sample_max)

def _compute_highest_edit_sim_from_details(details: Any) -> float:
\
\
\
\
       
    if not isinstance(details, list) or not details:
        return 0.0
    per_sample_max: List[float] = []
    for r in details:
        if not isinstance(r, dict):
            continue
        ref = r.get("reference_code")
        passed = r.get("passed_candidate_codes")
        if not ref or not isinstance(ref, str):
            continue
        if not isinstance(passed, list) or not passed:
            continue
        scores: List[float] = []
        for cand in passed:
            if not cand or not isinstance(cand, str):
                continue
            try:
                scores.append(float(calculate_edit_similarity(ref, cand)))
            except Exception:
                continue
        if scores:
            per_sample_max.append(max(scores))
    if not per_sample_max:
        return 0.0
    return sum(per_sample_max) / len(per_sample_max)


def _load_existing_runs(out_dir: Path) -> Tuple[Dict[Tuple[Any, ...], Dict[str, Any]], List[Dict[str, Any]]]:
\
\
\
\
       
    best_by_key: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    all_runs: List[Dict[str, Any]] = []

    if not out_dir.exists():
        return best_by_key, all_runs

    for p in out_dir.glob("*.json"):
                
        if p.name in {"summary.json"}:
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        meta = data.get("meta")
        metrics = data.get("metrics")
        if not isinstance(meta, dict) or not isinstance(metrics, dict):
            continue

                                                                         
        if "highest_bleu" not in metrics:
            try:
                metrics["highest_bleu"] = _compute_highest_bleu_from_details(data.get("details"))
            except Exception:
                                                                        
                metrics["highest_bleu"] = 0.0
        if "highest_edit_sim" not in metrics:
            try:
                metrics["highest_edit_sim"] = _compute_highest_edit_sim_from_details(data.get("details"))
            except Exception:
                metrics["highest_edit_sim"] = 0.0

        try:
            key = _run_key(
                model=str(meta.get("model", "")),
                n_samples=int(meta.get("n_samples", 0)),
                temperature=float(meta.get("temperature", 0.0)),
                top_p=_norm_optional_float(meta.get("top_p")),
                seed=int(meta.get("seed", 0)),
                jsonl_path=meta.get("jsonl_path"),
                limit=meta.get("limit"),
                base_url=str(meta.get("base_url", "")),
                use_jsonl_prompt=bool(meta.get("use_jsonl_prompt", False)),
                enable_mythril_check=bool(meta.get("enable_mythril_check", False)),
                mythril_timeout=meta.get("mythril_timeout"),
                mythril_severities=meta.get("mythril_severities"),
                mythril_bin=meta.get("mythril_bin"),
                force_single_n=bool(meta.get("force_single_n", False)),
                    llm_request_workers=int(meta.get("llm_request_workers", 1) or 1),
                    max_ir_change_rate=_norm_optional_float(meta.get("max_ir_change_rate")),
                max_orig_sim=_norm_optional_float(meta.get("max_orig_sim")),
                    engine=str(meta.get("engine", "llm") or "llm"),
                    sguard_dir=meta.get("sguard_dir"),
                    sguard_use_simplified_contract=bool(meta.get("use_simplified_contract", False)),
                    rag_mode=str(meta.get("rag_mode", "off") or "off"),
                    rag_index_path=meta.get("rag_index_path"),
                    rag_build_from_jsonl=meta.get("rag_build_from_jsonl"),
                    rag_build_limit=meta.get("rag_build_limit"),
                    rag_top_k=meta.get("rag_top_k"),
                    rag_max_demos=meta.get("rag_max_demos"),
                    rag_max_chars_each=meta.get("rag_max_chars_each"),
                    rag_max_added_tokens=meta.get("rag_max_added_tokens"),
                    rag_mmr_lambda=_norm_optional_float(meta.get("rag_mmr_lambda")),
                    rag_fusion_weights=meta.get("rag_fusion_weights"),
            )
        except Exception:
            continue

        run = {
            "config": {
                "model": str(meta.get("model", "")),
                "n_samples": int(meta.get("n_samples", 0)),
                "temperature": float(meta.get("temperature", 0.0)),
                "top_p": _norm_optional_float(meta.get("top_p")),
                "seed": int(meta.get("seed", 0)),
                "jsonl_path": meta.get("jsonl_path"),
                "limit": meta.get("limit"),
                "base_url": str(meta.get("base_url", "")),
                "use_jsonl_prompt": bool(meta.get("use_jsonl_prompt", False)),
                "enable_mythril_check": bool(meta.get("enable_mythril_check", False)),
                "mythril_timeout": meta.get("mythril_timeout"),
                "mythril_severities": meta.get("mythril_severities"),
                "mythril_bin": meta.get("mythril_bin"),
                "force_single_n": bool(meta.get("force_single_n", False)),
                "llm_request_workers": int(meta.get("llm_request_workers", 1) or 1),
                "max_ir_change_rate": _norm_optional_float(meta.get("max_ir_change_rate")),
                "max_orig_sim": _norm_optional_float(meta.get("max_orig_sim")),
                "engine": str(meta.get("engine", "llm") or "llm"),
                "sguard_dir": meta.get("sguard_dir"),
                "use_simplified_contract": bool(meta.get("use_simplified_contract", False)),
                "rag_mode": str(meta.get("rag_mode", "off") or "off"),
                "rag_index_path": meta.get("rag_index_path"),
                "rag_build_from_jsonl": meta.get("rag_build_from_jsonl"),
                "rag_build_limit": meta.get("rag_build_limit"),
                "rag_top_k": meta.get("rag_top_k"),
                "rag_max_demos": meta.get("rag_max_demos"),
                "rag_max_chars_each": meta.get("rag_max_chars_each"),
                "rag_max_added_tokens": meta.get("rag_max_added_tokens"),
                "rag_mmr_lambda": _norm_optional_float(meta.get("rag_mmr_lambda")),
                "rag_fusion_weights": meta.get("rag_fusion_weights"),
            },
            "metrics": metrics,
            "output": str(p),
        }
        all_runs.append(run)

        mtime = p.stat().st_mtime
        prev = best_by_key.get(key)
        if prev is None:
            best_by_key[key] = {"run": run, "mtime": mtime}
        else:
            if mtime > prev["mtime"]:
                best_by_key[key] = {"run": run, "mtime": mtime}

                            
    best_flat: Dict[Tuple[Any, ...], Dict[str, Any]] = {k: v["run"] for k, v in best_by_key.items()}
    return best_flat, all_runs


def _config_key(model: str, n_samples: int, temperature: float, top_p: Optional[float], rag_mode: str) -> str:
    tp = "none" if top_p is None else f"{top_p:g}"
                                                                                        
    rm = str(rag_mode or "off").strip().lower()
    return f"model={model}|n={n_samples}|temp={temperature:g}|top_p={tp}|rag={rm}"

def _preferred_csv_columns(summary_rows: List[Dict[str, Any]]) -> List[str]:
\
\
       
    if not summary_rows:
        return []
    all_cols = sorted({k for row in summary_rows for k in row.keys() if isinstance(k, str)})

    def _pairs(base: str) -> List[str]:
        return [f"{base}_mean", f"{base}_std"]

                                       
    preferred: List[str] = ["config_key", "num_runs"]
    for base in [
        "solved_rate",
        "pass@1",
        "pass@5",
        "pass@10",
                     
        "run_wall_time_sec",
        "sample_time_sec_avg",
        "sample_gen_time_sec_avg",
        "sample_verify_time_sec_avg",
        "llm_total_tokens",
        "llm_prompt_tokens",
        "llm_completion_tokens",
        "llm_requests",
        "llm_tokens_per_sample",
                                                                   
        "ir_sim",
        "highest_ir_sim",
        "ir_change_rate",
        "lowest_ir_change_rate",
                    
        "highest_bleu",
        "highest_edit_sim",
        "bleu",
        "bleu_all",
        "bleu_solved",
        "bleu_unsolved",
        "edit_sim",
        "edit_sim_all",
        "edit_sim_solved",
        "edit_sim_unsolved",
    ]:
        preferred.extend(_pairs(base))

                                 
    buckets = list(BUCKET_ORDER) + ["OTHER"]
    for b in buckets:
        for base in [
            f"type_n_{b}",
            f"solved_rate_{b}",
            f"pass@1_{b}",
            f"pass@5_{b}",
            f"pass@10_{b}",
        ]:
            preferred.extend(_pairs(base))

                                 
    out: List[str] = []
    seen = set()
    for c in preferred:
        if c in all_cols and c not in seen:
            out.append(c)
            seen.add(c)
    for c in all_cols:
        if c not in seen:
            out.append(c)
            seen.add(c)
    return out


def main():
    parser = argparse.ArgumentParser(description="系统化评测：多 seed / 多采样超参 sweep + 汇总统计")
    parser.add_argument("--db-path", default="sqlite:///smart_contracts.db", help="数据库路径")
    parser.add_argument("--jsonl-path", type=str, default=None, help="JSONL测试集路径 (可选，如指定则从JSONL加载)")
    parser.add_argument("--limit", type=int, default=None, help="评估样本数量")
    parser.add_argument("--n-samples", type=int, default=5, help="每个样本生成的候选数 (n)")
    parser.add_argument("--model", type=str, required=True, help="模型名称")
    parser.add_argument("--api-key", type=str, default="empty", help="API Key (默认读取 OPENAI_API_KEY)")
    parser.add_argument("--base-url", type=str, default="http://localhost:8000/v1", help="API Base URL")
    parser.add_argument(
        "--engine",
        type=str,
        default="llm",
        choices=["llm", "sguardplus", "contracttinker"],
        help="评测引擎：llm（默认，调用 OpenAI-compatible LLMFixer）或 sguardplus（调用 sGuardPlus 补丁器）",
    )

    parser.add_argument("--temperatures", type=str, default="0.7", help="逗号分隔，如 0.3,0.7")
    parser.add_argument("--top-ps", type=str, default="none", help="逗号分隔，如 none,0.9,0.95")
    parser.add_argument("--seeds", type=str, default="0,1,2,3,4", help="逗号分隔，如 0,1,2,3,4")
    parser.add_argument("--max-tokens", type=int, default=None, help="生成最大 token 数")
    parser.add_argument(
        "--use-jsonl-prompt",
        action="store_true",
        help="当指定 --jsonl-path 时：使用 JSONL 的 instruction/input 作为真实提示词生成（不从 DB 重建 prompt）；DB 仍用于验证（编译/Slither）",
    )
    parser.add_argument("--enable-mythril-check", action="store_true", help="启用 Mythril 验证（评估时会纳入成功判定）")
    parser.add_argument("--mythril-timeout", type=int, default=30, help="Mythril 单样本超时(秒)")
    parser.add_argument(
        "--mythril-severities",
        type=str,
        default=None,
        help="逗号分隔的 Mythril 严重级别过滤，例如: high,medium；为空则使用默认(high,medium)",
    )
    parser.add_argument("--mythril-bin", type=str, default="myth", help="Mythril 可执行文件名/路径（默认 myth）")
    parser.add_argument(
        "--force-single-n",
        action="store_true",
        help="强制将 n-samples 拆成循环 n 次 (每次请求 n=1)，用于可控对比实验（忽略模型/provider 是否支持 n>1）",
    )
    parser.add_argument(
        "--llm-request-workers",
        type=int,
        default=1,
        help="当走“循环 n 次（每次 n=1）”时，用多少线程并发发送 LLM 请求（仅生成阶段；默认 1=串行）",
    )
    parser.add_argument(
        "--max-ir-change-rate",
        type=float,
        default=None,
        help="可选：IR 变化率上限阈值。若候选 ir_change_rate > 阈值，则即使验证通过也按失败处理（例如 0.5）。",
    )
    parser.add_argument(
        "--max-orig-sim",
        type=float,
        default=None,
        help="可选：与原始函数代码的文本相似度上限阈值。若 similarity >= 阈值，则即使验证通过也按失败处理（用于抑制“原样输出/几乎不改”）。例如 0.995。",
    )
    parser.add_argument(
        "--sguard-dir",
        type=str,
        default=None,
        help="当 --engine=sguardplus 时：sGuardPlus-main 目录路径",
    )
    parser.add_argument(
        "--sguard-use-simplified-contract",
        action="store_true",
        help="当 --engine=sguardplus 时：用函数上下文构造简化合约作为输入（推荐用于函数级数据集）",
    )
    parser.add_argument(
        "--contracttinker-dir",
        type=str,
        default=None,
        help="当 --engine=contracttinker 时：LLM4SMAPR/ContractTinker 目录路径（默认自动推断为 repo_root/LLM4SMAPR/ContractTinker）",
    )
    parser.add_argument(
        "--contracttinker-validator-model",
        type=str,
        default="gpt-4",
        help="当 --engine=contracttinker 时：ContractTinker 的 validator 模型名（默认 gpt-4）",
    )
    parser.add_argument(
        "--contracttinker-enable-call-graph",
        action="store_true",
        help="当 --engine=contracttinker 时：启用 slither CLI call-graph + dot 解析（需要额外依赖，默认关闭）",
    )
    parser.add_argument("--sguard-timeout", type=int, default=600, help="当 --engine=sguardplus 时：每个合约运行超时(秒)")
    parser.add_argument("--node-bin", type=str, default="node", help="当 --engine=sguardplus 时：node 可执行文件")
    parser.add_argument("--python-bin", type=str, default="python", help="当 --engine=sguardplus 时：python 可执行文件（用于 slither_func2vec）")
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
        "--record-baseline",
        action="store_true",
        help="可选：评测时额外对“原始函数代码”跑一遍验证，并写入 details[*].baseline_verification，用于诊断工具是否能检出原始漏洞。",
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
        help="RAG usage mode for LLM engine: off=disable; always=prepend retrieved demos before the user prompt.",
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

    parser.add_argument("--out-dir", type=str, required=True, help="输出目录（会写入多份结果 + 汇总）")
    parser.add_argument("--verbose", action="store_true", help="详细日志（建议小规模调试）")
    parser.add_argument(
        "--print-llm-responses",
        action="store_true",
        help="打印每次生成的 LLM 原始完整回复到控制台（不写入结果 JSON；并行时输出可能交错）",
    )
    parser.add_argument(
        "--llm-responses-out",
        type=str,
        default=None,
        help="可选：将每个 sample 的每个 candidate 的 LLM 原始完整回复追加写入 JSONL 文件（若给的是目录，则每个 run 写到该目录下独立文件）",
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
    parser.add_argument("--resume", action="store_true", help="扫描 out-dir 已有结果并跳过相同配置的评测，同时纳入汇总")
    parser.add_argument("--workers", type=int, default=1, help="并行评测 worker 数（>1 可显著提速，但会提高 API 并发/资源占用）")
    parser.add_argument(
        "--executor",
        type=str,
        default="thread",
        choices=["thread", "process"],
        help="并行执行器类型：thread（默认，适合 IO/API）或 process（隔离更强但启动/序列化开销更大）",
    )
    parser.add_argument("--sample-workers", type=int, default=1, help="单次评估(run)内部的样本并行 worker 数（默认串行）")
    parser.add_argument(
        "--sample-executor",
        type=str,
        default="process",
        choices=["thread", "process"],
        help="run 内部并行执行器：process(默认，隔离 env/solc 更安全) 或 thread",
    )
    parser.add_argument("--keep-going", action="store_true", help="有 run 失败时继续跑完其它 run，并在最后汇总失败信息")

    args = parser.parse_args()

    temperatures = _parse_csv_floats(args.temperatures)
    top_ps = _parse_top_ps(args.top_ps)
    seeds = _parse_csv_ints(args.seeds)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    runs: List[Dict[str, Any]] = []
    done: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    if args.resume:
        done, _all_existing = _load_existing_runs(out_dir)
        if done:
            print(f"🔁 Resume enabled: found {len(done)} unique completed runs in {out_dir}")
            runs.extend(list(done.values()))

    total = len(temperatures) * len(top_ps) * len(seeds)
    run_idx = 0

                    
    tasks: List[Dict[str, Any]] = []
    for temperature in temperatures:
        for top_p in top_ps:
            for seed in seeds:
                run_idx += 1
                key = _run_key(
                    model=args.model,
                    n_samples=args.n_samples,
                    temperature=temperature,
                    top_p=top_p,
                    seed=seed,
                    jsonl_path=args.jsonl_path,
                    limit=args.limit,
                    base_url=args.base_url,
                    use_jsonl_prompt=bool(args.use_jsonl_prompt),
                    enable_mythril_check=bool(args.enable_mythril_check),
                    mythril_timeout=args.mythril_timeout,
                    mythril_severities=args.mythril_severities,
                    mythril_bin=args.mythril_bin,
                    force_single_n=bool(getattr(args, "force_single_n", False)),
                    llm_request_workers=int(getattr(args, "llm_request_workers", 1) or 1),
                    max_ir_change_rate=getattr(args, "max_ir_change_rate", None),
                    max_orig_sim=getattr(args, "max_orig_sim", None),
                    engine=str(getattr(args, "engine", "llm") or "llm"),
                    sguard_dir=getattr(args, "sguard_dir", None),
                    sguard_use_simplified_contract=bool(getattr(args, "sguard_use_simplified_contract", False)),
                    rag_mode=str(getattr(args, "rag_mode", "off") or "off"),
                    rag_index_path=getattr(args, "rag_index_path", None),
                    rag_build_from_jsonl=getattr(args, "rag_build_from_jsonl", None),
                    rag_build_limit=getattr(args, "rag_build_limit", None),
                    rag_top_k=getattr(args, "rag_top_k", None),
                    rag_max_demos=getattr(args, "rag_max_demos", None),
                    rag_max_chars_each=getattr(args, "rag_max_chars_each", None),
                    rag_max_added_tokens=getattr(args, "rag_max_added_tokens", None),
                    rag_mmr_lambda=getattr(args, "rag_mmr_lambda", None),
                    rag_fusion_weights=getattr(args, "rag_fusion_weights", None),
                )
                if args.resume and key in done:
                    print(
                        f"\n[{run_idx}/{total}] Skip (already exists): "
                        f"model={args.model}, n={args.n_samples}, temp={temperature}, top_p={top_p}, seed={seed}"
                    )
                    continue

                                    
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                run_name = (
                    f"eval_{args.model}_n{args.n_samples}_t{temperature:g}_p"
                    f"{('none' if top_p is None else f'{top_p:g}')}_rag{str(getattr(args, 'rag_mode', 'off') or 'off')}"
                    f"_seed{seed}_{stamp}_{time.time_ns()}"
                )
                output_path = out_dir / f"{run_name}.json"
                                                                                         
                llm_out = getattr(args, "llm_responses_out", None)
                if llm_out:
                    try:
                        p = Path(str(llm_out))
                        if p.exists() and p.is_dir():
                            llm_out = str(p / f"{run_name}.llm_responses.jsonl")
                    except Exception:
                                                                     
                        llm_out = str(llm_out)

                eval_args = argparse.Namespace(
                    db_path=args.db_path,
                    jsonl_path=args.jsonl_path,
                    limit=args.limit,
                    n_samples=args.n_samples,
                    model=args.model,
                    api_key=args.api_key,
                    base_url=args.base_url,
                    output=str(output_path),
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=args.max_tokens,
                    seed=seed,
                    verbose=args.verbose,
                    print_llm_responses=bool(getattr(args, "print_llm_responses", False)),
                    llm_responses_out=llm_out,
                    reasoning_effort=getattr(args, "reasoning_effort", None),
                    max_output_tokens=getattr(args, "max_output_tokens", None),
                    sample_workers=args.sample_workers,
                    sample_executor=args.sample_executor,
                    use_jsonl_prompt=bool(args.use_jsonl_prompt),
                    enable_mythril_check=bool(args.enable_mythril_check),
                    mythril_timeout=args.mythril_timeout,
                    mythril_severities=args.mythril_severities,
                    mythril_bin=args.mythril_bin,
                    strict_verification=bool(getattr(args, "strict_verification", False)),
                    mythril_uncertain_as_pass=bool(getattr(args, "mythril_uncertain_as_pass", True)),
                    record_baseline=bool(getattr(args, "record_baseline", False)),
                    baseline_only=bool(getattr(args, "baseline_only", False)),
                    force_single_n=bool(getattr(args, "force_single_n", False)),
                    llm_request_workers=int(getattr(args, "llm_request_workers", 1) or 1),
                    max_ir_change_rate=getattr(args, "max_ir_change_rate", None),
                    max_orig_sim=getattr(args, "max_orig_sim", None),
                    engine=str(getattr(args, "engine", "llm") or "llm"),
                    sguard_dir=getattr(args, "sguard_dir", None),
                    sguard_timeout=int(getattr(args, "sguard_timeout", 600) or 600),
                    node_bin=str(getattr(args, "node_bin", "node") or "node"),
                    python_bin=str(getattr(args, "python_bin", "python") or "python"),
                    use_simplified_contract=bool(getattr(args, "sguard_use_simplified_contract", False)),
                    contracttinker_dir=getattr(args, "contracttinker_dir", None),
                    contracttinker_validator_model=str(getattr(args, "contracttinker_validator_model", "gpt-4") or "gpt-4"),
                    contracttinker_enable_call_graph=bool(getattr(args, "contracttinker_enable_call_graph", False)),
                                                                            
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

                tasks.append(
                    {
                        "run_no": run_idx,
                        "total": total,
                        "key": key,
                        "temperature": temperature,
                        "top_p": top_p,
                        "seed": seed,
                        "output_path": output_path,
                        "eval_args": eval_args,
                    }
                )

    def _worker(task: Dict[str, Any]) -> Dict[str, Any]:
                                         
                                                                    
                                   
        prev_tqdm_disable = os.environ.get("TQDM_DISABLE")
        should_disable_inner_tqdm = (int(getattr(args, "workers", 1) or 1) > 1) and (len(tasks) > 1)
        if should_disable_inner_tqdm:
            os.environ["TQDM_DISABLE"] = "1"

        run_no = task["run_no"]
        temperature = task["temperature"]
        top_p = task["top_p"]
        seed = task["seed"]
        output_path = task["output_path"]
        eval_args = task["eval_args"]

        try:
            _safe_print(
                f"\n[{run_no}/{total}] Running: model={args.model}, n={args.n_samples}, "
                f"temp={temperature}, top_p={top_p}, seed={seed}"
            )

                             
            engine = str(getattr(eval_args, "engine", "llm") or "llm").strip().lower()
            if engine == "sguardplus":
                from scripts.evaluate_sguardplus import run_evaluation as run_sguardplus                

                output_data = run_sguardplus(eval_args)
            elif engine == "contracttinker":
                from scripts.evaluate_contracttinker import run_evaluation as run_contracttinker                

                output_data = run_contracttinker(eval_args)
            else:
                output_data = run_evaluation(eval_args)

                                                                                                       
            try:
                metrics = output_data.get("metrics")
                if isinstance(metrics, dict) and "highest_bleu" not in metrics:
                    metrics["highest_bleu"] = _compute_highest_bleu_from_details(output_data.get("details"))
            except Exception:
                                                         
                pass

                                                                                                                      
            try:
                metrics = output_data.get("metrics")
                if isinstance(metrics, dict) and "highest_edit_sim" not in metrics:
                    metrics["highest_edit_sim"] = _compute_highest_edit_sim_from_details(output_data.get("details"))
            except Exception:
                pass

                                                                                                         
            try:
                meta = output_data.get("meta")
                if isinstance(meta, dict):
                    if "api_key" in meta and meta.get("api_key"):
                        meta["api_key"] = "<redacted>"
            except Exception:
                pass

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)

            run_record = {
                "config": {
                    "model": args.model,
                    "n_samples": args.n_samples,
                    "temperature": temperature,
                    "top_p": top_p,
                    "seed": seed,
                    "jsonl_path": args.jsonl_path,
                    "limit": args.limit,
                    "base_url": args.base_url,
                    "use_jsonl_prompt": bool(args.use_jsonl_prompt),
                    "enable_mythril_check": bool(args.enable_mythril_check),
                    "mythril_timeout": args.mythril_timeout,
                    "mythril_severities": args.mythril_severities,
                    "mythril_bin": args.mythril_bin,
                    "rag_mode": str(getattr(args, "rag_mode", "off") or "off"),
                    "rag_index_path": getattr(args, "rag_index_path", None),
                    "rag_build_from_jsonl": getattr(args, "rag_build_from_jsonl", None),
                    "rag_build_limit": int(getattr(args, "rag_build_limit", 5000) or 5000),
                    "rag_top_k": int(getattr(args, "rag_top_k", 3) or 3),
                    "rag_max_demos": int(getattr(args, "rag_max_demos", 3) or 3),
                    "rag_max_chars_each": int(getattr(args, "rag_max_chars_each", 800) or 800),
                    "rag_max_added_tokens": getattr(args, "rag_max_added_tokens", None),
                    "rag_mmr_lambda": float(getattr(args, "rag_mmr_lambda", 0.7) or 0.7),
                    "rag_fusion_weights": str(getattr(args, "rag_fusion_weights", "0.35,0.35,0.2,0.1") or "0.35,0.35,0.2,0.1"),
                },
                "metrics": output_data.get("metrics", {}),
                "output": str(output_path),
            }
            return run_record
        finally:
                                                                                              
            if prev_tqdm_disable is None:
                os.environ.pop("TQDM_DISABLE", None)
            else:
                os.environ["TQDM_DISABLE"] = prev_tqdm_disable

               
    if args.workers <= 1 or not tasks:
        iterable = tasks
        if tqdm is not None and tasks:
            iterable = tqdm(tasks, total=len(tasks), desc="system_evaluate", unit="run")
        for task in iterable:
            try:
                run_record = _worker(task)
                runs.append(run_record)
                if args.resume:
                    done[task["key"]] = run_record
            except Exception:
                                     
                raise
    else:
        max_workers = max(1, int(args.workers))
        Executor = ThreadPoolExecutor if args.executor == "thread" else ProcessPoolExecutor
        failures: List[Dict[str, Any]] = []

        with Executor(max_workers=max_workers) as ex:
            future_to_task: Dict[Future, Dict[str, Any]] = {}
            for task in tasks:
                future_to_task[ex.submit(_worker, task)] = task

            completed_iter = as_completed(future_to_task)
            if tqdm is not None and tasks:
                completed_iter = tqdm(completed_iter, total=len(tasks), desc="system_evaluate", unit="run")
            for fut in completed_iter:
                task = future_to_task[fut]
                try:
                    run_record = fut.result()
                    runs.append(run_record)
                    if args.resume:
                        done[task["key"]] = run_record
                except Exception as e:
                    tb = traceback.format_exc()
                    failures.append(
                        {
                            "run_no": task.get("run_no"),
                            "temperature": task.get("temperature"),
                            "top_p": task.get("top_p"),
                            "seed": task.get("seed"),
                            "error": repr(e),
                            "traceback": tb,
                        }
                    )
                    _safe_print(
                        f"\n❌ Run failed: temp={task.get('temperature')}, top_p={task.get('top_p')}, seed={task.get('seed')}"
                    )
                    if not args.keep_going:
                                                 
                        for other_fut in future_to_task:
                            other_fut.cancel()
                        raise

        if failures:
            fail_path = out_dir / "failures.json"
            with open(fail_path, "w", encoding="utf-8") as f:
                json.dump({"failures": failures}, f, indent=2, ensure_ascii=False)
            print(f"\n⚠️ Some runs failed. Wrote failure details to: {fail_path}")

                                         
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for r in runs:
        cfg = r["config"]
        key = _config_key(cfg["model"], cfg["n_samples"], cfg["temperature"], cfg["top_p"], str(cfg.get("rag_mode", "off") or "off"))
        grouped.setdefault(key, []).append(r)

    summary_rows: List[Dict[str, Any]] = []
    metric_names = set()
    for r in runs:
        metric_names.update(r.get("metrics", {}).keys())
    metric_names = {m for m in metric_names if isinstance(m, str)}

    for key, items in grouped.items():
        row: Dict[str, Any] = {"config_key": key, "num_runs": len(items)}
        for m in sorted(metric_names):
            vals = [float(it["metrics"].get(m, 0.0)) for it in items]
            mean, std = _mean_std(vals)
            row[f"{m}_mean"] = mean
            row[f"{m}_std"] = std
        summary_rows.append(row)

                                   
    if any("solved_rate_mean" in r for r in summary_rows):
        summary_rows.sort(key=lambda x: x.get("solved_rate_mean", 0.0), reverse=True)

    summary = {
        "meta": {
            "created_at": datetime.now().isoformat(),
            "out_dir": str(out_dir),
            "total_runs": len(runs),
            "grid": {
                "temperatures": temperatures,
                "top_ps": top_ps,
                "seeds": seeds,
            },
            "base": {
                "model": args.model,
                "n_samples": args.n_samples,
                "jsonl_path": args.jsonl_path,
                "limit": args.limit,
                "base_url": args.base_url,
            },
        },
        "runs": runs,
        "aggregate": summary_rows,
    }

    summary_path = out_dir / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

                       
    csv_path = out_dir / "summary.csv"
    if summary_rows:
        columns = _preferred_csv_columns(summary_rows)
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(",".join(columns) + "\n")
            for row in summary_rows:
                f.write(",".join(str(row.get(c, "")) for c in columns) + "\n")

    print(f"\n✅ Done. Wrote:\n- {summary_path}\n- {csv_path}\n- {len(runs)} run files in {out_dir}")


if __name__ == "__main__":
    main()


