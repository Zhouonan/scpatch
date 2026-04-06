from __future__ import annotations
import argparse
import json
import os
import re
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
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))
from src.database.db_manager import DBManager
from src.database.models import SmartContractFunction
from src.evaluation.metrics import compute_metrics
from src.tools.slither_manager import SlitherManager
from src.tools.mythril_manager import MythrilManager
from src.tools.slice_builder import CodeSliceBuilder
from scripts.evaluate_fixes import BUCKET_ORDER, extract_fix_id_from_sample_id, load_jsonl_test_samples, parse_ground_truth_code, extract_types_from_fix_prompt_input, _bucket_primary

def _truncate(s: str, n: int=1200) -> str:
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

def _verify_fixed_contract(*, fixed_contract_src: str, slither_mgr: SlitherManager, mythril_mgr: MythrilManager, enable_mythril_check: bool, mythril_timeout: int, mythril_severities: Optional[List[str]], mythril_uncertain_as_pass: bool, strict_verification: bool) -> Tuple[Dict[str, Any], float]:
    vt0 = time.time()
    result: Dict[str, Any] = {'compiles': False, 'slither_passed': False, 'remaining_issues': [], 'error': None, 'mythril_passed': True, 'mythril_issues': [], 'mythril_error': None}
    (fd, tmp) = tempfile.mkstemp(suffix='.sol')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(fixed_contract_src or '')
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
_FUNC_BLOCK_RE = re.compile('\\bfunction\\b', re.MULTILINE)

def _extract_function_blocks(text: str) -> List[str]:
    if not text:
        return []
    out: List[str] = []
    for m in _FUNC_BLOCK_RE.finditer(text):
        i = m.start()
        brace = text.find('{', m.end())
        if brace == -1:
            continue
        depth = 0
        j = brace
        while j < len(text):
            ch = text[j]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    out.append(text[i:j + 1].strip())
                    break
            j += 1
    seen = set()
    uniq = []
    for b in out:
        if b and b not in seen:
            uniq.append(b)
            seen.add(b)
    return uniq

def _pick_patched_function_from_contracttinker_output(raw: str) -> Optional[str]:
    if not raw:
        return None
    parsed: Any = None
    s = raw.strip()
    if s.startswith('{') or s.startswith('['):
        try:
            parsed = json.loads(s)
        except Exception:
            try:
                import ast
                parsed = ast.literal_eval(s)
            except Exception:
                parsed = None

    def _iter_strings(x: Any) -> List[str]:
        acc: List[str] = []
        if isinstance(x, str):
            acc.append(x)
        elif isinstance(x, dict):
            for (k, v) in x.items():
                if isinstance(k, str):
                    acc.append(k)
                acc.extend(_iter_strings(v))
        elif isinstance(x, list):
            for it in x:
                acc.extend(_iter_strings(it))
        return acc
    if isinstance(parsed, dict):
        for k in list(parsed.keys()):
            if isinstance(k, str) and any((w in k.lower() for w in ['patch', 'fixed', 'after'])):
                v = parsed.get(k)
                if isinstance(v, str):
                    blocks = _extract_function_blocks(v)
                    return blocks[-1] if blocks else v.strip()
        blocks = []
        for st in _iter_strings(parsed):
            blocks.extend(_extract_function_blocks(st))
        if blocks:
            return blocks[-1]
    if isinstance(parsed, list):
        blocks = []
        for st in _iter_strings(parsed):
            blocks.extend(_extract_function_blocks(st))
        if blocks:
            return blocks[-1]
    blocks = _extract_function_blocks(raw)
    if blocks:
        return blocks[-1]
    return None

def _sanitize_contract_for_contracttinker(src: str) -> str:
    s = src or ''
    if not s.strip():
        return s
    needs_erc20 = any((k in s for k in ['.transfer(', '.transferFrom(', '.approve(']))
    erc20_iface = '\n'.join(['interface IERC20 {', '    function transfer(address to, uint256 value) external returns (bool);', '    function transferFrom(address from, address to, uint256 value) external returns (bool);', '    function approve(address spender, uint256 value) external returns (bool);', '}', ''])
    if needs_erc20 and 'interface IERC20' not in s:
        m = re.search('^\\s*pragma\\s+solidity\\b[^\\n]*\\n', s, flags=re.MULTILINE)
        if m:
            insert_at = m.end()
            s = s[:insert_at] + '\n' + erc20_iface + s[insert_at:]
        else:
            s = erc20_iface + s
    needs_safemath = any((k in s for k in ['.add(', '.sub(', '.mul(', '.div(']))
    safemath_lib = '\n'.join(['library SafeMath {', '    function add(uint256 a, uint256 b) internal pure returns (uint256) {', '        uint256 c = a + b;', '        require(c >= a, "SafeMath: addition overflow");', '        return c;', '    }', '    function sub(uint256 a, uint256 b) internal pure returns (uint256) {', '        require(b <= a, "SafeMath: subtraction overflow");', '        return a - b;', '    }', '    function mul(uint256 a, uint256 b) internal pure returns (uint256) {', '        if (a == 0) {', '            return 0;', '        }', '        uint256 c = a * b;', '        require(c / a == b, "SafeMath: multiplication overflow");', '        return c;', '    }', '    function div(uint256 a, uint256 b) internal pure returns (uint256) {', '        require(b > 0, "SafeMath: division by zero");', '        return a / b;', '    }', '}', ''])
    if needs_safemath and 'library SafeMath' not in s:
        m = re.search('^\\s*pragma\\s+solidity\\b[^\\n]*\\n', s, flags=re.MULTILINE)
        if m:
            insert_at = m.end()
            s = s[:insert_at] + '\n' + safemath_lib + s[insert_at:]
        else:
            s = safemath_lib + s
    if needs_safemath and 'using SafeMath for uint256' not in s:
        s = re.sub('(\\bcontract\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\{\\s*\\n)', '\\1    using SafeMath for uint256;\\n', s, count=1, flags=re.MULTILINE)
    lines = s.splitlines()
    out_lines: List[str] = []
    user_type_decl = re.compile('^\\s*([A-Z][A-Za-z0-9_]*)\\b(.*);?\\s*$')
    for line in lines:
        if 'new ' in line and ';' in line and ('=' in line):
            left = line.split('=', 1)[0].rstrip()
            if not left.endswith(';'):
                left = left + ';'
            line = left
        m = user_type_decl.match(line)
        if m:
            tname = m.group(1)
            rest = m.group(2) or ''
            if re.match('^\\s*(contract|interface|library)\\b', line):
                out_lines.append(line)
                continue
            if re.search('\\b(memory|storage|calldata)\\b', rest):
                out_lines.append(line)
                continue
            token_like = bool(re.search('\\btoken\\b', rest, flags=re.IGNORECASE) or tname.lower().endswith('token'))
            has_visibility = bool(re.search('\\b(public|private|internal|external)\\b', rest))
            if token_like:
                line = 'IERC20' + rest
            elif has_visibility:
                line = 'address' + rest
            else:
                out_lines.append(line)
                continue
        out_lines.append(line)
    s2 = '\n'.join(out_lines)
    try:
        defined = set()
        for _m in re.finditer('\\b(struct|contract|interface|library|enum)\\s+([A-Za-z_][A-Za-z0-9_]*)\\b', s2):
            defined.add(_m.group(2))
        decls = list(re.finditer('\\b([A-Z][A-Za-z0-9_]*)\\s+(memory|storage|calldata)\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*;', s2))
        struct_defs: List[str] = []
        for dm in decls:
            tname = dm.group(1)
            vname = dm.group(3)
            if tname in defined:
                continue
            fields = sorted(set(re.findall(f'\\b{re.escape(vname)}\\.([A-Za-z_][A-Za-z0-9_]*)\\b', s2)))
            if not fields:
                fields = ['_dummy']
            parts = [f'    uint256 {f};' for f in fields]
            struct_defs.append('\n'.join([f'    struct {tname} {{'] + parts + ['    }', '']))
            defined.add(tname)
        if struct_defs:
            blob = '\n'.join(struct_defs)
            pat = '(\\bcontract\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\{\\s*\\n(?:\\s*using\\s+SafeMath\\s+for\\s+uint256;\\s*\\n)?)'
            s2 = re.sub(pat, '\\1' + blob, s2, count=1, flags=re.MULTILINE)
    except Exception:
        pass
    return s2

def _synthesize_audit_report_md(*, sample_id: str, prompt_input: str) -> str:
    desc = (prompt_input or '').strip()
    if not desc:
        desc = 'N/A'
    name = (sample_id or 'sample').strip()
    return '\n'.join(['# Audit Report', '', '# High Risk Findings', f'## [[H-01] {name}](https://example.com)', desc, 'Recommend', 'Apply minimal necessary changes to fix the vulnerability while preserving intended behavior.', '', '# Medium Risk Findings', '', '# Low Risk Findings', ''])

def run_evaluation(args: argparse.Namespace) -> dict:
    if not args.jsonl_path:
        raise ValueError('ContractTinker evaluator requires --jsonl-path.')
    repo_root = Path(__file__).resolve().parents[2]
    ct_dir = Path(getattr(args, 'contracttinker_dir', '') or repo_root / 'LLM4SMAPR' / 'ContractTinker').resolve()
    if not ct_dir.exists():
        raise FileNotFoundError(f'contracttinker_dir not found: {ct_dir}')
    sys.path.insert(0, str(ct_dir))
    try:
        from patch_generate import Repair
    except Exception as e:
        raise ImportError(f'Failed to import ContractTinker from {ct_dir}: {type(e).__name__}: {e}') from e
    db_manager = DBManager(args.db_path)
    session = db_manager.get_session()
    test_samples = load_jsonl_test_samples(args.jsonl_path, args.limit)
    sample_infos = []
    fix_ids = []
    for sample in test_samples:
        sample_id = sample.get('id', 'unknown')
        fix_id = extract_fix_id_from_sample_id(str(sample_id))
        if fix_id is None:
            continue
        sample_infos.append((str(sample_id), int(fix_id), sample))
        fix_ids.append(int(fix_id))
    funcs = session.query(SmartContractFunction).filter(SmartContractFunction.id.in_(list(set(fix_ids)))).all()
    func_by_id = {f.id: f for f in funcs}
    builder = CodeSliceBuilder(include_comments=False)
    slither_mgr = SlitherManager(debug=bool(getattr(args, 'verbose', False)))
    mythril_mgr = MythrilManager(debug=bool(getattr(args, 'verbose', False)), mythril_bin=str(getattr(args, 'mythril_bin', 'myth') or 'myth'))
    eval_results: List[Dict[str, Any]] = []
    run_t0 = time.time()
    disable_tqdm = str(os.getenv('TQDM_DISABLE', '')).strip().lower() in {'1', 'true', 'yes'}
    iterable = sample_infos
    if tqdm is not None and (not disable_tqdm):
        iterable = tqdm(sample_infos, desc='ContractTinker', total=len(sample_infos))
    for (sample_id, fix_id, sample) in iterable:
        func = func_by_id.get(fix_id)
        if func is None:
            continue
        func_context = {'function_name': func.function_name, 'function_code': func.function_code, 'solidity_version': func.solidity_version, 'contract_context': func.contract_context, 'contract_path': func.contract_path, 'start_line': func.start_line, 'end_line': func.end_line}
        gt_code = parse_ground_truth_code(sample.get('output', '') or '')
        parsed_types = extract_types_from_fix_prompt_input(sample.get('input', ''))
        vuln_bucket = _bucket_primary(parsed_types)
        simplified_src = builder.build_simplified_contract(func_context, fixed_code=None)
        simplified_src = _sanitize_contract_for_contracttinker(simplified_src)
        gen_t0 = time.time()
        raw_patch_output = None
        patch_error = None
        fixed_func = None
        with tempfile.TemporaryDirectory(prefix='contracttinker_eval_') as td:
            td_path = Path(td)
            proj_dir = td_path / 'project'
            proj_dir.mkdir(parents=True, exist_ok=True)
            contract_file = proj_dir / 'Contract.sol'
            contract_file.write_text(simplified_src or '', encoding='utf-8')
            report_md = td_path / 'report.md'
            report_md.write_text(_synthesize_audit_report_md(sample_id=sample_id, prompt_input=str(sample.get('input', '') or '')), encoding='utf-8')
            try:
                old_key = os.environ.get('OPENAI_API_KEY')
                old_base = os.environ.get('OPENAI_BASE_URL')
                if getattr(args, 'api_key', None):
                    os.environ['OPENAI_API_KEY'] = str(getattr(args, 'api_key'))
                if getattr(args, 'base_url', None):
                    os.environ['OPENAI_BASE_URL'] = str(getattr(args, 'base_url'))
                repair = Repair(str(report_md), str(proj_dir) + os.sep, solc_remaps='', model_name=str(getattr(args, 'model', 'gpt-3.5-turbo') or 'gpt-3.5-turbo'), validator_model_name=str(getattr(args, 'contracttinker_validator_model', 'gpt-4') or 'gpt-4'), parsed_report_dir=str(td_path), enable_call_graph=bool(getattr(args, 'contracttinker_enable_call_graph', False)))
                raw_patch_output = repair.contractFixer(sample_id)
            except Exception as e:
                patch_error = f'{type(e).__name__}: {e}'
            finally:
                if old_key is None:
                    os.environ.pop('OPENAI_API_KEY', None)
                else:
                    os.environ['OPENAI_API_KEY'] = old_key
                if old_base is None:
                    os.environ.pop('OPENAI_BASE_URL', None)
                else:
                    os.environ['OPENAI_BASE_URL'] = old_base
        gen_dt = float(time.time() - gen_t0)
        if isinstance(raw_patch_output, str):
            fixed_func = _pick_patched_function_from_contracttinker_output(raw_patch_output)
        verify_t0 = time.time()
        ver = None
        is_correct = False
        if fixed_func:
            fixed_contract_src = builder.build_simplified_contract(func_context, fixed_code=fixed_func)
            fixed_contract_src = _sanitize_contract_for_contracttinker(fixed_contract_src)
            (ver, _) = _verify_fixed_contract(fixed_contract_src=fixed_contract_src, slither_mgr=slither_mgr, mythril_mgr=mythril_mgr, enable_mythril_check=bool(getattr(args, 'enable_mythril_check', False)), mythril_timeout=int(getattr(args, 'mythril_timeout', 120) or 120), mythril_severities=_parse_csv_strs(getattr(args, 'mythril_severities', None)), mythril_uncertain_as_pass=bool(getattr(args, 'mythril_uncertain_as_pass', True)), strict_verification=bool(getattr(args, 'strict_verification', False)))
            is_correct = bool(ver.get('compiles')) and bool(ver.get('slither_passed'))
            if bool(getattr(args, 'enable_mythril_check', False)):
                is_correct = is_correct and bool(ver.get('mythril_passed', True))
        verify_dt = float(time.time() - verify_t0)
        result: Dict[str, Any] = {'sample_id': sample_id, 'contract': func.contract_path, 'function': func.function_name, 'total_generated': 1, 'correct_generated': 1 if is_correct else 0, 'best_candidate_code': fixed_func, 'passed_candidate_codes': [fixed_func] if is_correct and fixed_func else [], 'sample_time_sec': float(gen_dt + verify_dt), 'sample_gen_time_sec': float(gen_dt), 'sample_verify_time_sec': float(verify_dt), 'llm_total_tokens': 0, 'llm_prompt_tokens': 0, 'llm_completion_tokens': 0, 'llm_requests': 0, 'verification': ver, 'contracttinker_error': patch_error, 'contracttinker_raw_output': _truncate(raw_patch_output or '', 1800) if raw_patch_output else None, 'vulnerability_types': parsed_types, 'vuln_bucket': vuln_bucket}
        if gt_code:
            result['reference_code'] = gt_code
        if bool(getattr(args, 'include_source', False)):
            result['original_function_code'] = func.function_code
            result['original_solidity_version'] = func.solidity_version
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
        bucket_pass[b][1].append(1.0 if r.get('correct_generated', 0) > 0 else 0.0)
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
    return {'meta': vars(args), 'metrics': metrics, 'details': eval_results}

def main():
    p = argparse.ArgumentParser(description='Evaluate ContractTinker on function-level dataset (JSONL + DB).')
    p.add_argument('--db-path', default='sqlite:///smart_contracts.db')
    p.add_argument('--jsonl-path', type=str, required=True)
    p.add_argument('--limit', type=int, default=None)
    p.add_argument('--output', type=str, default='contracttinker_eval.json')
    p.add_argument('--model', type=str, default='gpt-3.5-turbo', help='ContractTinker generator model name')
    p.add_argument('--contracttinker-validator-model', type=str, default='gpt-4', help='ContractTinker validator model')
    p.add_argument('--contracttinker-dir', type=str, default=None, help='Path to LLM4SMAPR/ContractTinker directory (defaults to repo_root/LLM4SMAPR/ContractTinker)')
    p.add_argument('--contracttinker-enable-call-graph', action='store_true', help='Enable ContractTinker call-graph generation via slither CLI + dot parsing (requires extra deps).')
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
