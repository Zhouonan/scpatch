#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, Iterable, List, Optional, Tuple

def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return d0 + d1

def _safe_len(s: Optional[str]) -> int:
    return len(s) if isinstance(s, str) else 0

def _iter_eval_files(input_dir: Path, pattern: str) -> Iterable[Path]:
    yield from sorted(input_dir.glob(pattern))

def _load_json(path: Path) -> Dict[str, Any]:
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)

def _compute_bleu_for_details(details: List[Dict[str, Any]]) -> Tuple[List[float], List[Dict[str, Any]]]:
    from src.evaluation.metrics import calculate_bleu, NLTK_AVAILABLE
    if not NLTK_AVAILABLE:
        raise RuntimeError('NLTK is not available. Install it (and its deps) first, e.g.\n  pip install nltk\nThen re-run this script.')
    bleu_scores: List[float] = []
    rows: List[Dict[str, Any]] = []
    for d in details:
        ref = d.get('reference_code')
        cand = d.get('best_candidate_code')
        if not ref or not cand:
            continue
        bleu = float(calculate_bleu(ref, cand))
        bleu_scores.append(bleu)
        rows.append({'sample_id': d.get('sample_id', ''), 'function': d.get('function', ''), 'contract': d.get('contract', ''), 'correct_generated': d.get('correct_generated', ''), 'total_generated': d.get('total_generated', ''), 'bleu': bleu, 'ref_chars': _safe_len(ref), 'cand_chars': _safe_len(cand)})
    return (bleu_scores, rows)

def _summarize_bleu(bleu_scores: List[float]) -> Dict[str, float]:
    if not bleu_scores:
        return {'count': 0, 'mean': 0.0, 'median': 0.0, 'p10': 0.0, 'p25': 0.0, 'p75': 0.0, 'p90': 0.0, 'min': 0.0, 'max': 0.0}
    s = sorted(bleu_scores)
    return {'count': float(len(bleu_scores)), 'mean': float(mean(bleu_scores)), 'median': float(median(bleu_scores)), 'p10': float(_percentile(s, 10)), 'p25': float(_percentile(s, 25)), 'p75': float(_percentile(s, 75)), 'p90': float(_percentile(s, 90)), 'min': float(s[0]), 'max': float(s[-1])}

def _filter_details(details: List[Dict[str, Any]], mode: str) -> List[Dict[str, Any]]:
    if mode == 'all':
        return details
    if mode == 'solved':
        return [d for d in details if (d.get('correct_generated', 0) or 0) > 0]
    if mode == 'unsolved':
        return [d for d in details if (d.get('correct_generated', 0) or 0) == 0]
    raise ValueError(f'Unknown filter_mode: {mode!r}')

def _print_file_report(path: Path, stored_bleu: Optional[float], recomputed_bleu: Optional[float], counts: Dict[str, int], summary: Dict[str, float], rows: List[Dict[str, Any]], show_examples: int, compact: bool) -> None:
    stored_str = 'None' if stored_bleu is None else f'{stored_bleu:.6f}'
    recomputed_str = 'None' if recomputed_bleu is None else f'{recomputed_bleu:.6f}'
    diff = None
    if stored_bleu is not None and recomputed_bleu is not None:
        diff = abs(stored_bleu - recomputed_bleu)
    if compact:
        diff_str = 'None' if diff is None else f'{diff:.3g}'
        print(f"{path.name}\tstored={stored_str}\trecomputed={recomputed_str}\tabs_diff={diff_str}\twith_pair={counts['with_pair']}/{counts['details']}\tmean={summary['mean']:.4f}\tmed={summary['median']:.4f}\tp10={summary['p10']:.4f}\tp90={summary['p90']:.4f}")
        return
    print(f'\n=== {path.name} ===')
    print(f'stored metrics.bleu: {stored_str}')
    print(f'recomputed bleu mean: {recomputed_str}' + (f'  (abs diff={diff:.6g})' if diff is not None else ''))
    print(f"counts: details={counts['details']}, with_pair={counts['with_pair']}, missing_ref={counts['missing_ref']}, missing_cand={counts['missing_cand']}")
    print(f"bleu stats: mean={summary['mean']:.6f}, median={summary['median']:.6f}, p10={summary['p10']:.6f}, p90={summary['p90']:.6f}, min={summary['min']:.6f}, max={summary['max']:.6f}")
    if show_examples > 0 and rows:
        rows_sorted = sorted(rows, key=lambda r: float(r['bleu']))
        low = rows_sorted[:show_examples]
        high = rows_sorted[-show_examples:][::-1]
        print('\nlowest BLEU samples:')
        for r in low:
            print(f"- sample_id={r['sample_id']} bleu={float(r['bleu']):.6f} ref_chars={r['ref_chars']} cand_chars={r['cand_chars']} func={r['function']}")
        print('\nhighest BLEU samples:')
        for r in high:
            print(f"- sample_id={r['sample_id']} bleu={float(r['bleu']):.6f} ref_chars={r['ref_chars']} cand_chars={r['cand_chars']} func={r['function']}")

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--input_dir', type=str, default='results/system_eval/qwen_sft_1216', help='Directory containing eval JSON files.')
    parser.add_argument('--pattern', type=str, default='eval_*.json', help='Glob pattern within input_dir.')
    parser.add_argument('--show_examples', type=int, default=5, help='Show N best/worst BLEU samples per file.')
    parser.add_argument('--filter_mode', type=str, default='all', choices=['all', 'solved', 'unsolved'], help='Filter samples before BLEU computation by correct_generated.')
    parser.add_argument('--compact', action='store_true', help='Print one TSV line per file (no top/bottom sample lists).')
    parser.add_argument('--aggregate', action='store_true', help='Also print an overall summary aggregated across all matched files.')
    parser.add_argument('--write_csv', action='store_true', help='Write per-sample BLEU rows to a CSV next to each JSON.')
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parent.parent
    import sys
    sys.path.insert(0, str(project_root))
    input_dir = (project_root / args.input_dir).resolve() if not Path(args.input_dir).is_absolute() else Path(args.input_dir)
    if not input_dir.exists():
        raise FileNotFoundError(f'input_dir not found: {input_dir}')
    eval_files = list(_iter_eval_files(input_dir, args.pattern))
    if not eval_files:
        raise FileNotFoundError(f'No files matched: dir={input_dir} pattern={args.pattern!r}')
    all_bleu_scores: List[float] = []
    all_rows: List[Dict[str, Any]] = []
    if args.compact:
        print('file\tstored\trecomputed\tabs_diff\twith_pair\tmean\tmed\tp10\tp90')
    for path in eval_files:
        data = _load_json(path)
        details = data.get('details', [])
        if not isinstance(details, list):
            raise ValueError(f'Unexpected JSON format: details is not a list in {path}')
        details_filtered = _filter_details(details, args.filter_mode)
        counts = {'details': len(details_filtered), 'with_pair': 0, 'missing_ref': 0, 'missing_cand': 0}
        for d in details_filtered:
            ref = d.get('reference_code')
            cand = d.get('best_candidate_code')
            if not ref:
                counts['missing_ref'] += 1
            if not cand:
                counts['missing_cand'] += 1
            if ref and cand:
                counts['with_pair'] += 1
        (bleu_scores, rows) = _compute_bleu_for_details(details_filtered)
        summary = _summarize_bleu(bleu_scores)
        stored_bleu = None
        if isinstance(data.get('metrics'), dict):
            stored = data['metrics'].get('bleu')
            stored_bleu = float(stored) if stored is not None else None
        recomputed_bleu = float(mean(bleu_scores)) if bleu_scores else None
        _print_file_report(path, stored_bleu, recomputed_bleu, counts, summary, rows, args.show_examples, compact=args.compact)
        if args.aggregate:
            all_bleu_scores.extend(bleu_scores)
            for r in rows:
                r2 = dict(r)
                r2['file'] = path.name
                all_rows.append(r2)
        if args.write_csv:
            out_csv = path.with_suffix('.bleu_verify.csv')
            with out_csv.open('w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['sample_id', 'function', 'contract', 'correct_generated', 'total_generated', 'bleu', 'ref_chars', 'cand_chars'])
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
            print(f'wrote: {out_csv}')
    if args.aggregate:
        overall = _summarize_bleu(all_bleu_scores)
        print('\n=== OVERALL (all matched files) ===')
        print(f"pairs={int(overall['count'])} mean={overall['mean']:.6f} median={overall['median']:.6f} p10={overall['p10']:.6f} p90={overall['p90']:.6f} min={overall['min']:.6f} max={overall['max']:.6f}")
if __name__ == '__main__':
    main()
