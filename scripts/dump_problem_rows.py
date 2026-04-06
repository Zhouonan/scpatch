#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
JSON_COLUMNS = ['vulnerability_types', 'label', 'slither_result', 'llm_audit', 'contract_context', 'caller_functions', 'called_functions', 'raw_data']

@dataclass
class RowIssue:
    issue_type: str
    details: str

def _try_json_load(value: Any) -> Tuple[Any, Optional[str]]:
    if value is None:
        return (None, None)
    if isinstance(value, (dict, list, int, float, bool)):
        return (value, None)
    if not isinstance(value, str):
        return (value, None)
    s = value.strip()
    if not s:
        return (value, None)
    try:
        return (json.loads(s), None)
    except Exception as e:
        return (value, f'{type(e).__name__}: {e}')

def _shape(v: Any) -> str:
    if v is None:
        return 'null'
    if isinstance(v, dict):
        return 'object'
    if isinstance(v, list):
        if not v:
            return 'array(empty)'
        t0 = _shape(v[0])
        return f'array({t0}..)'
    return type(v).__name__

def _check_list_of_dicts(obj: Any, field_name: str, required_keys: Optional[List[str]]=None) -> List[RowIssue]:
    issues: List[RowIssue] = []
    if obj is None:
        return issues
    if not isinstance(obj, list):
        issues.append(RowIssue(f'{field_name}.type', f'expected list, got {_shape(obj)}'))
        return issues
    if not obj:
        return issues
    elem_types = Counter((_shape(x) for x in obj))
    if len(elem_types) > 1:
        issues.append(RowIssue(f'{field_name}.mixed_types', f'element types: {dict(elem_types)}'))
    bad_examples: List[str] = []
    missing_key_examples: List[str] = []
    for x in obj[:50]:
        if isinstance(x, dict):
            if required_keys:
                for k in required_keys:
                    if k not in x or x.get(k) in (None, ''):
                        missing_key_examples.append(f'missing/empty {k} in keys={sorted(x.keys())}')
                        break
        elif x is None:
            bad_examples.append('null')
        else:
            bad_examples.append(f'{type(x).__name__}: {repr(x)[:80]}')
    if bad_examples:
        issues.append(RowIssue(f'{field_name}.non_object_elems', '; '.join(bad_examples[:10])))
    if missing_key_examples:
        issues.append(RowIssue(f'{field_name}.missing_keys', '; '.join(missing_key_examples[:10])))
    return issues

def _analyze_row(row: Dict[str, Any]) -> Tuple[List[RowIssue], Dict[str, Any]]:
    issues: List[RowIssue] = []
    parsed: Dict[str, Any] = {}
    for col in JSON_COLUMNS:
        raw = row.get(col)
        (val, err) = _try_json_load(raw)
        parsed[col] = val
        if err:
            issues.append(RowIssue(f'{col}.malformed_json', err))
    ctx = parsed.get('contract_context')
    if ctx is not None and (not isinstance(ctx, dict)):
        issues.append(RowIssue('contract_context.type', f'expected object, got {_shape(ctx)}'))
        return (issues, parsed)
    contract_context: Dict[str, Any] = ctx or {}
    issues.extend(_check_list_of_dicts(contract_context.get('state_variables'), 'contract_context.state_variables', ['code']))
    issues.extend(_check_list_of_dicts(contract_context.get('structures'), 'contract_context.structures', ['code']))
    issues.extend(_check_list_of_dicts(contract_context.get('modifiers'), 'contract_context.modifiers', ['code']))
    issues.extend(_check_list_of_dicts(parsed.get('called_functions'), 'called_functions', ['code']))
    issues.extend(_check_list_of_dicts(parsed.get('caller_functions'), 'caller_functions', ['code']))
    return (issues, parsed)

def _fetch_rows(conn: sqlite3.Connection, dataset_name: Optional[str], limit: int) -> List[Dict[str, Any]]:
    cur = conn.cursor()
    where = []
    params: List[Any] = []
    if dataset_name:
        where.append('dataset_name = ?')
        params.append(dataset_name)
    where_sql = 'WHERE ' + ' AND '.join(where) if where else ''
    fetch_n = max(limit * 50, 2000)
    sql = f'SELECT * FROM smart_contract_functions {where_sql} LIMIT ?'
    params2 = params + [fetch_n]
    cur.execute(sql, params2)
    rows = cur.fetchall()
    colnames = [d[0] for d in cur.description]
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = {colnames[i]: r[i] for i in range(len(colnames))}
        out.append(d)
    return out

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', type=str, default='smart_contracts.db')
    ap.add_argument('--dataset-name', type=str, default=None)
    ap.add_argument('--limit', type=int, default=50, help='max problematic rows to write')
    ap.add_argument('--out', type=str, default='problem_rows.jsonl')
    args = ap.parse_args()
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    rows = _fetch_rows(conn, args.dataset_name, args.limit)
    problem_rows: List[Dict[str, Any]] = []
    issue_counter: Counter[str] = Counter()
    issue_examples: Dict[str, str] = {}
    for row in rows:
        (issues, parsed) = _analyze_row(row)
        if not issues:
            continue
        for iss in issues:
            issue_counter[iss.issue_type] += 1
            if iss.issue_type not in issue_examples:
                issue_examples[iss.issue_type] = iss.details
        payload = dict(row)
        payload['_issues'] = [{'type': i.issue_type, 'details': i.details} for i in issues]
        payload['_json_parsed_shapes'] = {k: _shape(parsed.get(k)) for k in JSON_COLUMNS}
        payload['_contract_context_shapes'] = {}
        ctx = parsed.get('contract_context')
        if isinstance(ctx, dict):
            payload['_contract_context_shapes'] = {'state_variables': _shape(ctx.get('state_variables')), 'structures': _shape(ctx.get('structures')), 'modifiers': _shape(ctx.get('modifiers'))}
        payload['_json_parsed'] = parsed
        problem_rows.append(payload)
        if len(problem_rows) >= args.limit:
            break
    with open(args.out, 'w', encoding='utf-8') as f:
        for pr in problem_rows:
            f.write(json.dumps(pr, ensure_ascii=False) + '\n')
    print('### done')
    print('db:', args.db)
    print('dataset_name:', args.dataset_name)
    print('written_problem_rows:', len(problem_rows))
    print('out:', args.out)
    print('\n### issue stats (top 30)')
    for (t, n) in issue_counter.most_common(30):
        ex = issue_examples.get(t, '')
        print(f'- {t}: {n}  (example: {ex})')
    conn.close()
if __name__ == '__main__':
    main()
