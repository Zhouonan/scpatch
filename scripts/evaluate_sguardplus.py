from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
try:
    from tqdm import tqdm
except Exception:
    tqdm = None
import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
from src.database.db_manager import DBManager
from src.database.models import SmartContractFunction
from src.evaluation.metrics import compute_metrics
from src.tools.slither_manager import SlitherManager
from src.tools.mythril_manager import MythrilManager
from src.tools.slice_builder import CodeSliceBuilder
from scripts.evaluate_fixes import BUCKET_ORDER, extract_fix_id_from_sample_id, load_jsonl_test_samples, parse_ground_truth_code, extract_types_from_fix_prompt_input, _bucket_primary

def _resolve_contract_path(p: str) -> Optional[str]:
    if not p:
        return None
    s = str(p)
    if os.path.exists(s):
        return os.path.abspath(s)
    cand = os.path.abspath(os.path.join(str(project_root), s))
    if os.path.exists(cand):
        return cand
    cand2 = os.path.abspath(os.path.join(os.getcwd(), s))
    if os.path.exists(cand2):
        return cand2
    return None
_FUNC_DECL_RE = re.compile('\\bfunction\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\(')

def _extract_function_code_from_contract(contract_src: str, function_name: str) -> Optional[str]:
    if not contract_src or not function_name:
        return None
    pat = re.compile(f'\\bfunction\\s+{re.escape(function_name)}\\s*\\(', re.MULTILINE)
    m = pat.search(contract_src)
    if not m:
        return None
    i = m.start()
    brace = contract_src.find('{', m.end())
    if brace == -1:
        return None
    depth = 0
    j = brace
    while j < len(contract_src):
        ch = contract_src[j]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return contract_src[i:j + 1].strip()
        j += 1
    return None

def _verify_fixed_contract(*, fixed_contract_src: str, slither_mgr: SlitherManager, mythril_mgr: MythrilManager, enable_mythril_check: bool, mythril_timeout: int, mythril_severities: Optional[List[str]], mythril_uncertain_as_pass: bool, strict_verification: bool) -> Tuple[Dict[str, Any], float]:
    vt0 = time.time()
    result: Dict[str, Any] = {'compiles': False, 'slither_passed': False, 'remaining_issues': [], 'error': None, 'mythril_passed': True, 'mythril_issues': [], 'mythril_error': None}
    (fd, tmp) = tempfile.mkstemp(suffix='.sol')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(fixed_contract_src)
        try:
            solc_path = slither_mgr.setup_solc_version(tmp) or 'solc'
            if solc_path == 'SOLCX_ENV':
                solc_path = 'solc'
            out = subprocess.run([solc_path, '--bin', tmp], capture_output=True, text=True, timeout=30)
            if out.returncode == 0:
                result['compiles'] = True
            else:
                result['compiles'] = False
                result['error'] = f'compile_failed: {_truncate(out.stderr)}'
        except FileNotFoundError:
            if strict_verification:
                result['compiles'] = False
                result['error'] = 'compile_failed: solc_not_found'
            else:
                result['compiles'] = True
        except subprocess.TimeoutExpired:
            result['compiles'] = False
            result['error'] = 'compile_failed: timeout'
        except Exception as e:
            if strict_verification:
                result['compiles'] = False
                result['error'] = f'compile_failed: {type(e).__name__}: {e}'
            else:
                result['compiles'] = True
        if not result['compiles']:
            return (result, float(time.time() - vt0))
        try:
            crit: List[str] = []
            with slither_mgr.analyze_contract(tmp) as sl:
                if not sl:
                    if strict_verification:
                        result['slither_passed'] = False
                        result['remaining_issues'] = ['slither_none']
                        result['error'] = 'slither_failed: slither_none'
                        return (result, float(time.time() - vt0))
                    result['slither_passed'] = True
                else:
                    try:
                        if hasattr(sl, 'run_detectors'):
                            sl.run_detectors()
                    except Exception:
                        pass
                    for det in getattr(sl, 'detectors', []) or []:
                        if hasattr(det, 'results'):
                            for res in det.results:
                                sev = getattr(res, 'severity', None)
                                if sev is None:
                                    sev = getattr(res, 'impact', None)
                                sev_s = str(sev).lower() if sev is not None else ''
                                if 'high' in sev_s or 'medium' in sev_s:
                                    desc = getattr(res, 'description', '') or ''
                                    check_name = getattr(res, 'check', det.ARGUMENT if hasattr(det, 'ARGUMENT') else 'UnknownCheck')
                                    crit.append(f'{check_name}: {desc}')
                    result['remaining_issues'] = crit
                    result['slither_passed'] = len(crit) == 0
                    if not result['slither_passed']:
                        result['error'] = 'slither_failed: issues'
        except FileNotFoundError:
            if strict_verification:
                result['slither_passed'] = False
                result['remaining_issues'] = ['slither_not_found']
                result['error'] = 'slither_failed: not_found'
            else:
                result['slither_passed'] = True
        except subprocess.TimeoutExpired:
            if strict_verification:
                result['slither_passed'] = False
                result['remaining_issues'] = ['slither_timeout']
                result['error'] = 'slither_failed: timeout'
            else:
                result['slither_passed'] = True
        except Exception as e:
            if strict_verification:
                result['slither_passed'] = False
                result['remaining_issues'] = [f'slither_error: {type(e).__name__}: {e}']
                result['error'] = 'slither_failed: error'
            else:
                result['slither_passed'] = True
        if enable_mythril_check:
            try:
                mr = mythril_mgr.analyze_contract(tmp, timeout=int(mythril_timeout), severities=mythril_severities if mythril_severities is not None else ('high', 'medium'), max_issues=50)
                mr_error = str(mr.error or '')
                uncertain = False
                if mr_error:
                    err_l = mr_error.lower()
                    uncertain = any((k in err_l for k in ['mythril_timeout', 'mythril_not_found', 'contract_not_found', 'mythril_error', 'mythril_rc=']))
                if mythril_uncertain_as_pass and uncertain:
                    result['mythril_passed'] = True
                else:
                    result['mythril_passed'] = bool(mr.passed)
                result['mythril_issues'] = mr.issues
                result['mythril_error'] = mr.error
                if not result['mythril_passed']:
                    result['error'] = 'mythril_failed: issues'
            except Exception as e:
                if strict_verification:
                    result['mythril_passed'] = False
                    result['mythril_error'] = f'{type(e).__name__}: {e}'
                    result['error'] = 'mythril_failed: error'
                else:
                    result['mythril_passed'] = True
                    result['mythril_error'] = f'{type(e).__name__}: {e}'
        return (result, float(time.time() - vt0))
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _truncate(s: str, n: int=800) -> str:
    s = (s or '').strip()
    if len(s) <= n:
        return s
    return s[:n] + '...<truncated>...'

def _parse_csv_strs(value: Optional[str]) -> Optional[List[str]]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    parts = [p.strip().lower() for p in s.split(',') if p.strip()]
    return parts or None

def _run_sguardplus_on_contract(*, contract_file: str, sguard_dir: str, node_bin: str, python_bin: str, timeout: int) -> Tuple[Optional[str], Optional[Dict[str, Any]], float]:
    t0 = time.time()
    sguard_dir = os.path.abspath(sguard_dir)
    if not os.path.isdir(sguard_dir):
        raise FileNotFoundError(f'sguard_dir not found: {sguard_dir}')
    with tempfile.TemporaryDirectory(prefix='sguardplus_') as td:
        td_path = Path(td)
        src_path = Path(contract_file)
        tmp_contract = td_path / src_path.name
        shutil.copyfile(contract_file, tmp_contract)
        env = dict(os.environ)
        env['PYTHON'] = python_bin
        cmd = [node_bin, 'src/index.js', str(tmp_contract)]
        out = subprocess.run(cmd, cwd=sguard_dir, capture_output=True, text=True, timeout=max(1, int(timeout)), env=env)
        report_path = str(tmp_contract) + '_vul_report.json'
        fixed_path = str(tmp_contract) + '.fixed.sol'
        vul_report = None
        if os.path.exists(report_path):
            try:
                with open(report_path, 'r', encoding='utf-8') as f:
                    vul_report = json.load(f)
            except Exception:
                vul_report = None
        if not os.path.exists(fixed_path):
            if vul_report is None:
                vul_report = {'_sguard_rc': out.returncode, '_sguard_stdout': _truncate(out.stdout or '', 1200), '_sguard_stderr': _truncate(out.stderr or '', 1200)}
            return (None, vul_report, float(time.time() - t0))
        try:
            with open(fixed_path, 'r', encoding='utf-8', errors='ignore') as f:
                fixed_src = f.read()
        except Exception:
            fixed_src = None
        if vul_report is None:
            vul_report = {'_sguard_rc': out.returncode, '_sguard_stdout': _truncate(out.stdout or '', 1200), '_sguard_stderr': _truncate(out.stderr or '', 1200)}
        return (fixed_src, vul_report, float(time.time() - t0))

def _run_sguardplus_on_source(*, contract_src: str, filename_hint: str, sguard_dir: str, node_bin: str, python_bin: str, timeout: int) -> Tuple[Optional[str], Optional[Dict[str, Any]], float]:
    with tempfile.TemporaryDirectory(prefix='sguardplus_src_') as td:
        td_path = Path(td)
        safe_name = re.sub('[^A-Za-z0-9_.-]+', '_', filename_hint or 'contract.sol')
        tmp_contract = td_path / safe_name
        tmp_contract.write_text(contract_src or '', encoding='utf-8')
        return _run_sguardplus_on_contract(contract_file=str(tmp_contract), sguard_dir=sguard_dir, node_bin=node_bin, python_bin=python_bin, timeout=timeout)

def run_evaluation(args: argparse.Namespace) -> dict:
    db_manager = DBManager(args.db_path)
    session = db_manager.get_session()
    if not args.jsonl_path:
        raise ValueError('sGuardPlus evaluator currently requires --jsonl-path (function-level test set).')
    test_samples = load_jsonl_test_samples(args.jsonl_path, args.limit)
    sample_infos = []
    fix_ids = []
    for sample in test_samples:
        sample_id = sample.get('id', 'unknown')
        fix_id = extract_fix_id_from_sample_id(sample_id)
        if fix_id is None:
            continue
        sample_infos.append((sample_id, fix_id, sample))
        fix_ids.append(fix_id)
    funcs = session.query(SmartContractFunction).filter(SmartContractFunction.id.in_(list(set(fix_ids)))).all()
    func_by_id = {f.id: f for f in funcs}
    use_simplified = bool(getattr(args, 'use_simplified_contract', True))
    builder = CodeSliceBuilder(include_comments=False)
    per_sample: List[Dict[str, Any]] = []
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for (sample_id, fix_id, sample) in sample_infos:
        func = func_by_id.get(fix_id)
        if func is None:
            continue
        contract_path = None
        if not use_simplified:
            contract_path = _resolve_contract_path(func.contract_path)
            if not contract_path:
                continue
        gt_code = parse_ground_truth_code(sample.get('output', '') or '')
        contract_name = None
        try:
            contract_name = (func.contract_context or {}).get('contract_name')
        except Exception:
            contract_name = None
        func_context = {'function_name': func.function_name, 'function_code': func.function_code, 'solidity_version': func.solidity_version, 'contract_context': func.contract_context, 'contract_path': func.contract_path}
        simplified_src = None
        if use_simplified:
            try:
                simplified_src = builder.build_simplified_contract(func_context, fixed_code=None)
            except Exception:
                simplified_src = None
        contract_key = str(contract_path) if contract_path else f'synthetic_fix_{fix_id}'
        row = {'sample_id': sample_id, 'fix_id': fix_id, 'contract_file': contract_key, 'original_contract_file': contract_path, 'contract_name': contract_name, 'function_name': func.function_name, 'original_function_code': func.function_code, 'original_solidity_version': func.solidity_version, 'jsonl_sample': sample, 'reference_code': gt_code if gt_code else None, 'simplified_contract_src': simplified_src}
        per_sample.append(row)
        groups.setdefault(contract_key, []).append(row)
    slither_mgr = SlitherManager(debug=bool(getattr(args, 'verbose', False)))
    mythril_mgr = MythrilManager(debug=bool(getattr(args, 'verbose', False)), mythril_bin=str(getattr(args, 'mythril_bin', 'myth') or 'myth'))
    contract_cache: Dict[str, Dict[str, Any]] = {}

    def _func_key(row: Dict[str, Any]) -> str:
        cn = row.get('contract_name') or ''
        fn = row.get('function_name') or ''
        if cn:
            return f'{cn}::{fn}'
        return str(fn)
    run_t0 = time.time()
    disable_tqdm = str(os.getenv('TQDM_DISABLE', '')).strip().lower() in {'1', 'true', 'yes'}
    contract_items = list(groups.items())
    it_contracts = contract_items
    if tqdm is not None and (not disable_tqdm):
        it_contracts = tqdm(contract_items, desc='sGuard+ (per-contract)', total=len(contract_items))
    for (contract_key, rows) in it_contracts:
        fixed_src = None
        vul_report = None
        gen_time_sec = 0.0
        if use_simplified:
            src = None
            for r in rows:
                if r.get('simplified_contract_src'):
                    src = r.get('simplified_contract_src')
                    break
            if src:
                (fixed_src, vul_report, gen_time_sec) = _run_sguardplus_on_source(contract_src=str(src), filename_hint=f'{contract_key}.sol', sguard_dir=str(getattr(args, 'sguard_dir')), node_bin=str(getattr(args, 'node_bin', 'node') or 'node'), python_bin=str(getattr(args, 'python_bin', 'python') or 'python'), timeout=int(getattr(args, 'sguard_timeout', 600) or 600))
        else:
            (fixed_src, vul_report, gen_time_sec) = _run_sguardplus_on_contract(contract_file=str(contract_key), sguard_dir=str(getattr(args, 'sguard_dir')), node_bin=str(getattr(args, 'node_bin', 'node') or 'node'), python_bin=str(getattr(args, 'python_bin', 'python') or 'python'), timeout=int(getattr(args, 'sguard_timeout', 600) or 600))
        supported_funcs = set()
        if isinstance(vul_report, dict):
            for (_k, items) in vul_report.items():
                if isinstance(items, list):
                    for it in items:
                        if isinstance(it, dict) and it.get('function_name'):
                            supported_funcs.add(str(it['function_name']))
        ver_result = None
        verify_time_sec = 0.0
        if fixed_src:
            (ver_result, verify_time_sec) = _verify_fixed_contract(fixed_contract_src=fixed_src, slither_mgr=slither_mgr, mythril_mgr=mythril_mgr, enable_mythril_check=bool(getattr(args, 'enable_mythril_check', False)), mythril_timeout=int(getattr(args, 'mythril_timeout', 120) or 120), mythril_severities=_parse_csv_strs(getattr(args, 'mythril_severities', None)), mythril_uncertain_as_pass=bool(getattr(args, 'mythril_uncertain_as_pass', True)), strict_verification=bool(getattr(args, 'strict_verification', False)))
        contract_cache[contract_key] = {'fixed_contract_src': fixed_src, 'vul_report': vul_report, 'supported_funcs': supported_funcs, 'gen_time_sec': gen_time_sec, 'verify_time_sec': verify_time_sec, 'verification': ver_result}
    eval_results: List[Dict[str, Any]] = []
    it_samples = per_sample
    if tqdm is not None and (not disable_tqdm):
        it_samples = tqdm(per_sample, desc='Project to samples', total=len(per_sample))
    for row in it_samples:
        ckey = row['contract_file']
        cache = contract_cache.get(ckey) or {}
        fixed_src = cache.get('fixed_contract_src')
        supported = cache.get('supported_funcs') or set()
        ver = cache.get('verification') or {}
        num_in_contract = len(groups.get(ckey) or []) or 1
        sample_gen_time = float(cache.get('gen_time_sec', 0.0) or 0.0) / num_in_contract
        sample_verify_time = float(cache.get('verify_time_sec', 0.0) or 0.0) / num_in_contract
        fk = _func_key(row)
        is_supported = fk in supported
        is_correct = False
        if is_supported and fixed_src and isinstance(ver, dict):
            is_correct = bool(ver.get('compiles')) and bool(ver.get('slither_passed'))
            if bool(getattr(args, 'enable_mythril_check', False)):
                is_correct = is_correct and bool(ver.get('mythril_passed', True))
        best_code = _extract_function_code_from_contract(fixed_src, str(row.get('function_name') or '')) if fixed_src and is_supported else None
        parsed_types = []
        js = row.get('jsonl_sample')
        if isinstance(js, dict):
            parsed_types = extract_types_from_fix_prompt_input(js.get('input', ''))
        vuln_bucket = _bucket_primary(parsed_types)
        result: Dict[str, Any] = {'sample_id': row.get('sample_id'), 'contract': row.get('original_contract_file') or row.get('contract_file'), 'function': row.get('function_name'), 'total_generated': 1, 'correct_generated': 1 if is_correct else 0, 'best_candidate_code': best_code, 'passed_candidate_codes': [best_code] if is_correct and best_code else [], 'sample_time_sec': float(sample_gen_time + sample_verify_time), 'sample_gen_time_sec': float(sample_gen_time), 'sample_verify_time_sec': float(sample_verify_time), 'llm_total_tokens': 0, 'llm_prompt_tokens': 0, 'llm_completion_tokens': 0, 'llm_requests': 0, 'sguard_supported': bool(is_supported), 'sguard_contract_verified': bool(is_correct), 'verification': ver, 'sguard_use_simplified_contract': bool(use_simplified), 'vulnerability_types': parsed_types, 'vuln_bucket': vuln_bucket}
        if row.get('reference_code'):
            result['reference_code'] = row.get('reference_code')
        if bool(getattr(args, 'include_source', False)):
            result['original_function_code'] = row.get('original_function_code')
            result['original_solidity_version'] = row.get('original_solidity_version')
        eval_results.append(result)
    metrics = compute_metrics(eval_results, k_values=[1])
    if 'pass@1' in metrics:
        metrics['pass@5'] = metrics['pass@1']
        metrics['pass@10'] = metrics['pass@1']
    k_values = [1]
    bucket_total = {k: 0 for k in BUCKET_ORDER + ['OTHER']}
    bucket_solved = {k: 0 for k in BUCKET_ORDER + ['OTHER']}
    bucket_pass = {b: {k: [] for k in k_values} for b in BUCKET_ORDER + ['OTHER']}
    for r in eval_results:
        b = r.get('vuln_bucket') or 'OTHER'
        if b not in bucket_total:
            b = 'OTHER'
        bucket_total[b] += 1
        if r.get('correct_generated', 0) > 0:
            bucket_solved[b] += 1
        n = int(r.get('total_generated', 0) or 0)
        c = int(r.get('correct_generated', 0) or 0)
        if n >= 1:
            bucket_pass[b][1].append(1.0 if c > 0 else 0.0)
    for b in BUCKET_ORDER + ['OTHER']:
        n = bucket_total[b]
        metrics[f'type_n_{b}'] = n
        metrics[f'solved_rate_{b}'] = bucket_solved[b] / n if n else 0.0
        metrics[f'pass@1_{b}'] = sum(bucket_pass[b][1]) / len(bucket_pass[b][1]) if bucket_pass[b][1] else 0.0
        metrics[f'pass@5_{b}'] = metrics[f'pass@1_{b}']
        metrics[f'pass@10_{b}'] = metrics[f'pass@1_{b}']
    run_wall = float(time.time() - run_t0)
    n_eval = len(eval_results) or 1
    metrics['run_wall_time_sec'] = run_wall
    metrics['sample_time_sec_avg'] = sum((float(r.get('sample_time_sec', 0.0) or 0.0) for r in eval_results)) / n_eval
    metrics['sample_gen_time_sec_avg'] = sum((float(r.get('sample_gen_time_sec', 0.0) or 0.0) for r in eval_results)) / n_eval
    metrics['sample_verify_time_sec_avg'] = sum((float(r.get('sample_verify_time_sec', 0.0) or 0.0) for r in eval_results)) / n_eval
    metrics['sguard_supported_rate'] = sum((1 for r in eval_results if bool(r.get('sguard_supported')))) / n_eval
    return {'meta': vars(args), 'metrics': metrics, 'details': eval_results}

def main():
    p = argparse.ArgumentParser(description='Evaluate sGuardPlus on function-level dataset (JSONL + DB).')
    p.add_argument('--db-path', default='sqlite:///smart_contracts.db')
    p.add_argument('--jsonl-path', type=str, required=True)
    p.add_argument('--limit', type=int, default=None)
    p.add_argument('--output', type=str, default='sguardplus_eval.json')
    p.add_argument('--model', type=str, default='sguardplus', help='Label name for this engine (for summary).')
    p.add_argument('--sguard-dir', type=str, required=True, help='Path to sGuardPlus-main directory')
    p.add_argument('--node-bin', type=str, default='node')
    p.add_argument('--python-bin', type=str, default='python', help='Python executable for slither_func2vec (__main__.py)')
    p.add_argument('--sguard-timeout', type=int, default=600, help='Timeout seconds for running sGuardPlus per contract')
    p.add_argument('--use-simplified-contract', action='store_true', help='用 DB 中的 function_context 构造一个可编译的简化合约作为 sGuardPlus 输入（推荐用于函数级评测）。')
    p.add_argument('--include-source', action='store_true')
    p.add_argument('--verbose', action='store_true')
    p.add_argument('--enable-mythril-check', action='store_true')
    p.add_argument('--mythril-timeout', type=int, default=120)
    p.add_argument('--mythril-severities', type=str, default=None)
    p.add_argument('--mythril-bin', type=str, default='myth')
    p.add_argument('--strict-verification', action='store_true')
    p.add_argument('--mythril-uncertain-as-pass', action='store_true')
    args = p.parse_args()
    out = run_evaluation(args)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f'Wrote: {args.output}')
if __name__ == '__main__':
    main()
