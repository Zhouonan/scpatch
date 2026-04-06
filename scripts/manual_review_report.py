import argparse
import json
import os
import re
import difflib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def extract_fix_id_from_sample_id(sample_id: str) -> Optional[int]:
    m = re.search('fix_(\\d+)', str(sample_id))
    if m:
        return int(m.group(1))
    try:
        return int(sample_id)
    except Exception:
        return None

def _safe_str(x: Any) -> str:
    return '' if x is None else str(x)

def _suspicious_flags(original_code: str, fixed_code: str) -> List[str]:
    flags: List[str] = []
    o = _safe_str(original_code)
    f = _safe_str(fixed_code)
    ol = o.lower()
    fl = f.lower()
    if 'tx.origin' in fl:
        flags.append('uses_tx_origin')
    if 'selfdestruct' in fl:
        flags.append('selfdestruct')
    if re.search('\\brevert\\s*\\(', fl) or re.search('\\bthrow\\b', fl) or 'require(false' in fl:
        flags.append('may_disable_functionality')
    if len(o.strip()) > 0:
        ratio = (len(f.strip()) + 1) / (len(o.strip()) + 1)
        if ratio < 0.5:
            flags.append('much_shorter_than_original')
    if '.call.value' in fl or 'call{value' in fl:
        flags.append('uses_low_level_call_value')
    return flags

def _unified_diff(a: str, b: str, fromfile: str, tofile: str) -> str:
    a_lines = _safe_str(a).splitlines(keepends=True)
    b_lines = _safe_str(b).splitlines(keepends=True)
    return ''.join(difflib.unified_diff(a_lines, b_lines, fromfile=fromfile, tofile=tofile, lineterm=''))

def _write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', errors='ignore')

def main():
    parser = argparse.ArgumentParser(description='Generate a manual review report for fix evaluation runs.')
    parser.add_argument('--eval-json', type=str, required=True, help='Path to eval_*.json produced by evaluate_fixes/system_evaluate')
    parser.add_argument('--out-dir', type=str, required=True, help='Output directory for report files')
    parser.add_argument('--db-path', type=str, default=None, help='DB path (default: read from eval meta if present)')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of samples in report')
    parser.add_argument('--only-suspicious', action='store_true', help='Only include samples with suspicious flags')
    args = parser.parse_args()
    eval_path = Path(args.eval_json)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = json.loads(eval_path.read_text(encoding='utf-8'))
    meta = data.get('meta') if isinstance(data.get('meta'), dict) else {}
    details = data.get('details') if isinstance(data.get('details'), list) else []
    db_path = args.db_path or meta.get('db_path') or 'sqlite:///smart_contracts.db'
    from src.database.db_manager import DBManager
    from src.database.models import SmartContractFunction
    db = DBManager(db_path)
    session = db.get_session()
    rows: List[Dict[str, Any]] = []
    for d in details:
        if not isinstance(d, dict):
            continue
        sample_id = d.get('sample_id')
        fix_id = extract_fix_id_from_sample_id(sample_id)
        if fix_id is None:
            continue
        func = session.query(SmartContractFunction).filter(SmartContractFunction.id == fix_id).first()
        original_code = getattr(func, 'function_code', None) if func is not None else None
        fixed_best = d.get('best_candidate_code')
        flags = _suspicious_flags(_safe_str(original_code), _safe_str(fixed_best))
        if args.only_suspicious and (not flags):
            continue
        row = {'sample_id': sample_id, 'fix_id': fix_id, 'function': d.get('function') or (getattr(func, 'function_name', None) if func is not None else None), 'contract': d.get('contract') or (getattr(func, 'contract_path', None) if func is not None else None), 'vuln_bucket': d.get('vuln_bucket'), 'vulnerability_types': d.get('vulnerability_types'), 'correct_generated': d.get('correct_generated'), 'total_generated': d.get('total_generated'), 'flags': flags, 'original_function_code': _safe_str(original_code), 'best_candidate_code': _safe_str(fixed_best), 'passed_candidate_codes': d.get('passed_candidate_codes') if isinstance(d.get('passed_candidate_codes'), list) else []}
        rows.append(row)
        if args.limit is not None and len(rows) >= int(args.limit):
            break
    rows.sort(key=lambda r: (0 if r.get('flags') else 1, -int(r.get('correct_generated') or 0)))
    index_lines: List[str] = []
    index_lines.append(f'# Manual Review Report\n')
    index_lines.append(f'- Eval: `{eval_path}`\n')
    index_lines.append(f'- DB: `{db_path}`\n')
    index_lines.append(f'- Samples in report: **{len(rows)}** (only_suspicious={bool(args.only_suspicious)})\n\n')
    index_lines.append('| sample_id | bucket | c/n | flags | file |\n')
    index_lines.append('|---|---:|---:|---|---|\n')
    for r in rows:
        sid = _safe_str(r.get('sample_id'))
        bucket = _safe_str(r.get('vuln_bucket'))
        c = int(r.get('correct_generated') or 0)
        n = int(r.get('total_generated') or 0)
        flags = ', '.join(r.get('flags') or [])
        fname = f'{sid}.md'.replace('/', '_')
        index_lines.append(f'| {sid} | {bucket} | {c}/{n} | {flags} | [{fname}]({fname}) |\n')
        page: List[str] = []
        page.append(f'# {sid}\n\n')
        page.append(f'- **bucket**: `{bucket}`\n')
        page.append(f"- **function**: `{_safe_str(r.get('function'))}`\n")
        page.append(f"- **contract**: `{_safe_str(r.get('contract'))}`\n")
        page.append(f'- **c/n**: {c}/{n}\n')
        page.append(f"- **types**: `{_safe_str(r.get('vulnerability_types'))}`\n")
        if flags:
            page.append(f'- **flags**: {flags}\n')
        page.append('\n## Diff (original -> best)\n\n')
        diff = _unified_diff(r.get('original_function_code', ''), r.get('best_candidate_code', ''), fromfile='original', tofile='best_candidate')
        page.append('```diff\n')
        page.append(diff if diff.strip() else '(no diff)\n')
        page.append('\n```\n\n')
        page.append('## Original function\n\n```solidity\n')
        page.append(r.get('original_function_code', ''))
        page.append('\n```\n\n')
        page.append('## Best candidate\n\n```solidity\n')
        page.append(r.get('best_candidate_code', ''))
        page.append('\n```\n\n')
        passed = r.get('passed_candidate_codes') or []
        if passed:
            page.append('## Other passed candidates (first 3)\n\n')
            for (i, cand) in enumerate(passed[:3], 1):
                page.append(f'### passed[{i}]\n\n```solidity\n{_safe_str(cand)}\n```\n\n')
        _write_text(out_dir / fname, ''.join(page))
    _write_text(out_dir / 'index.md', ''.join(index_lines))
    print(f'Wrote report to: {out_dir}/index.md')
if __name__ == '__main__':
    import sys
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    main()
