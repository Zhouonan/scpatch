import sys
import json
import argparse
import random
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
project_root = Path(__file__).resolve().parents[2]
sys.path.append(str(project_root))
from src.database.db_manager import DBManager
from src.database.models import SmartContractFunction
from src.database.models_fix import VulnerabilityFix
from src.tools.prompt_formatter import PromptFormatter
from src.tools.swc_mapper import map_types_to_swc_ids
BUCKET_ORDER = ['REENTRANCY', 'ACCESS_CONTROL', 'UNCHECKED_CALL', 'ARITHMETIC', 'BAD_RANDOMNESS', 'TIMESTAMP_DEPENDENCE', 'DOS', 'STORAGE']

def _normalize_type_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    s = str(v).strip()
    if not s:
        return []
    parts = [p.strip() for p in s.split(',')]
    return [p for p in parts if p]

def _looks_like_access_control(t: str) -> bool:
    s = (t or '').lower()
    s = s.replace('_', ' ').replace('-', ' ')
    return any((k in s for k in ['access control', 'authorization', 'authentication', 'privilege', 'onlyowner', 'missing access control']))

def map_types_to_8_buckets_or_keep_original(raw_types: List[str], swc_ids: List[str]) -> List[str]:
    raw_types = _normalize_type_list(raw_types)
    swc_ids = _normalize_type_list(swc_ids)
    if not swc_ids and raw_types:
        swc_ids = map_types_to_swc_ids(raw_types)
    swc_set = set(swc_ids)
    buckets = set()
    if 'SWC-107' in swc_set:
        buckets.add('REENTRANCY')
    if 'SWC-104' in swc_set:
        buckets.add('UNCHECKED_CALL')
    if 'SWC-101' in swc_set:
        buckets.add('ARITHMETIC')
    if 'SWC-120' in swc_set:
        buckets.add('BAD_RANDOMNESS')
    if 'SWC-116' in swc_set:
        buckets.add('TIMESTAMP_DEPENDENCE')
    if 'SWC-113' in swc_set or 'SWC-126' in swc_set or 'SWC-128' in swc_set:
        buckets.add('DOS')
    if 'SWC-109' in swc_set or 'SWC-124' in swc_set:
        buckets.add('STORAGE')
    if any((_looks_like_access_control(t) for t in raw_types)):
        buckets.add('ACCESS_CONTROL')
    if not buckets:
        return raw_types
    return [b for b in BUCKET_ORDER if b in buckets]

def _bucket_keys_from_display_types(display_types: List[str], mode: str, primary_strategy: str='order', bucket_sizes: Optional[Dict[str, int]]=None) -> List[str]:
    display_types = _normalize_type_list(display_types)
    bucket_hits = [t for t in BUCKET_ORDER if t in set(display_types)]
    if not bucket_hits:
        return ['OTHER']
    if mode == 'multi':
        return bucket_hits
    if primary_strategy == 'rare' and bucket_sizes:

        def _size(k: str) -> int:
            return int(bucket_sizes.get(k, 10 ** 9))
        best = min(bucket_hits, key=lambda k: (_size(k), BUCKET_ORDER.index(k)))
        return [best]
    return bucket_hits[:1]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='导出智能合约修复微调数据集（指令格式 JSONL）')
    default_db_path = f'sqlite:///{project_root}/smart_contracts.db'
    parser.add_argument('--db-path', type=str, default=default_db_path, help='数据库连接字符串')
    parser.add_argument('--output-dir', type=str, default=str(project_root / 'data/processed/fix_sft'), help='输出目录')
    parser.add_argument('--only-successful', action='store_true', default=False, help='仅导出编译与Slither都通过的修复')
    parser.add_argument('--min-quality', type=float, default=None, help='按修复质量分数下限过滤（需要存在 fix_quality_score）')
    parser.add_argument('--dataset-names', type=str, nargs='*', default=None, help='按数据集名称过滤')
    parser.add_argument('--max-samples', type=int, default=None, help='最多导出多少条样本')
    parser.add_argument('--split-ratios', type=float, nargs='*', default=None, help='划分比例列表（支持任意份数），例如: --split-ratios 0.8 0.1 0.05 0.05。若提供则忽略 train/val/test-ratio。')
    parser.add_argument('--split-names', type=str, nargs='*', default=None, help='与 split-ratios 对应的 split 名称列表，例如: --split-names train val test extra。默认自动生成 train/val/test/split_3...')
    parser.add_argument('--train-ratio', type=float, default=0.8, help='训练集比例（旧参数）')
    parser.add_argument('--val-ratio', type=float, default=0.1, help='验证集比例（旧参数）')
    parser.add_argument('--test-ratio', type=float, default=0.1, help='测试集比例（旧参数）')
    parser.add_argument('--seed', type=int, default=42, help='随机种子')
    parser.add_argument('--include-explanation', action='store_true', default=False, help='输出中附带修复说明')
    parser.add_argument('--save-raw', action='store_true', default=False, help='同时导出原始字段 JSON 方便调试')
    parser.add_argument('--stratify-by-type', action='store_true', default=False, help='按漏洞类型分层划分 train/val/test，避免类型分配不均（仍输出一套 train/val/test.jsonl）')
    parser.add_argument('--primary-bucket-strategy', type=str, default='order', choices=['order', 'rare'], help='当需要 primary 分桶时的主桶选择策略：order=按固定优先级；rare=若样本含多个桶则优先选择全局更稀有的小桶')
    return parser.parse_args()

def _validate_split_ratios(ratios: List[float]):
    if not ratios:
        raise ValueError('split ratios 不能为空')
    if any((r is None for r in ratios)):
        raise ValueError('split ratios 不能包含 None')
    if any((float(r) < 0 for r in ratios)):
        raise ValueError(f'split ratios 不能为负数: {ratios}')
    total = float(sum(ratios))
    if not abs(total - 1.0) < 1e-06:
        raise ValueError(f'split ratios 之和必须为 1，当前为 {total}, ratios={ratios}')

def _default_split_names(n: int) -> List[str]:
    if n <= 0:
        return []
    base = ['train', 'val', 'test']
    if n <= len(base):
        return base[:n]
    rest = [f'split_{i}' for i in range(len(base), n)]
    return base + rest

def resolve_splits_from_args(args: argparse.Namespace) -> Tuple[List[str], List[float]]:
    if args.split_ratios is not None and len(args.split_ratios) > 0:
        ratios = [float(x) for x in args.split_ratios]
    else:
        ratios = [float(args.train_ratio), float(args.val_ratio), float(args.test_ratio)]
    _validate_split_ratios(ratios)
    if args.split_names is not None and len(args.split_names) > 0:
        names = [str(x) for x in args.split_names]
        if len(names) != len(ratios):
            raise ValueError(f'--split-names 数量({len(names)})必须与 --split-ratios 数量({len(ratios)})一致')
    else:
        names = _default_split_names(len(ratios))
    if len(set(names)) != len(names):
        raise ValueError(f'split names 不能重复: {names}')
    return (names, ratios)

def fetch_fix_pairs(db: DBManager, only_successful: bool, min_quality: float=None, dataset_names: List[str]=None) -> List[Dict[str, Any]]:
    session = db.get_session()
    try:
        query = session.query(VulnerabilityFix, SmartContractFunction).join(SmartContractFunction, VulnerabilityFix.function_id == SmartContractFunction.id)
        if only_successful:
            query = query.filter(VulnerabilityFix.compiles.is_(True)).filter(VulnerabilityFix.slither_passed.is_(True))
        if min_quality is not None:
            query = query.filter(VulnerabilityFix.fix_quality_score >= min_quality)
        if dataset_names:
            query = query.filter(SmartContractFunction.dataset_name.in_(dataset_names))
        results = query.all()
        pairs: List[Dict[str, Any]] = []
        for (fix, func_obj) in results:
            code_slice = fix.original_code or func_obj.function_code
            pairs.append({'fix_pair_id': None, 'fix_id': func_obj.id, 'function_name': func_obj.function_name, 'function_id': func_obj.id, 'dataset_name': func_obj.dataset_name, 'code_slice': code_slice, 'fixed_code': fix.fixed_code, 'vulnerability_types': fix.vulnerabilities_fixed or [], 'swc_ids': getattr(fix, 'swc_ids', None) or [], 'is_training': None, 'is_validation': None, 'is_test': None, 'quality_checked': fix.is_verified, 'quality_score': fix.fix_quality_score, 'created_at': str(fix.created_at), 'annotation': func_obj.llm_audit, 'compiles': fix.compiles, 'slither_passed': fix.slither_passed, 'fix_version': fix.fix_version, 'fix_analysis': fix.fix_analysis, 'model_name': fix.model_name, 'fix_quality_score': fix.fix_quality_score})
        return pairs
    finally:
        session.close()

def split_dataset(data: List[Dict[str, Any]], split_ratios: List[float], seed: int) -> List[List[Dict[str, Any]]]:
    _validate_split_ratios(split_ratios)
    rng = random.Random(seed)
    items = list(data)
    rng.shuffle(items)
    n = len(items)
    splits: List[List[Dict[str, Any]]] = []
    start = 0
    for (i, r) in enumerate(split_ratios):
        if i == len(split_ratios) - 1:
            end = n
        else:
            end = start + int(n * float(r))
        splits.append(items[start:end])
        start = end
    return splits

def _stratified_split_dataset(data: List[Dict[str, Any]], key_fn, split_ratios: List[float], seed: int) -> Tuple[List[List[Dict[str, Any]]], Dict[str, Dict[str, int]]]:
    _validate_split_ratios(split_ratios)
    rng = random.Random(seed)
    strata: Dict[str, List[Dict[str, Any]]] = {}
    for x in data:
        k = str(key_fn(x))
        strata.setdefault(k, []).append(x)
    splits: List[List[Dict[str, Any]]] = [[] for _ in split_ratios]
    stats: Dict[str, Dict[str, int]] = {}
    for k in sorted(strata.keys()):
        items = list(strata[k])
        rng.shuffle(items)
        n = len(items)
        counts: List[int] = []
        assigned = 0
        for (i, r) in enumerate(split_ratios):
            if i == len(split_ratios) - 1:
                c = n - assigned
            else:
                c = int(n * float(r))
            counts.append(c)
            assigned += c
        offset = 0
        per_key_stats: Dict[str, int] = {'total': n}
        for (i, c) in enumerate(counts):
            chunk = items[offset:offset + c]
            splits[i].extend(chunk)
            per_key_stats[f'split_{i}'] = len(chunk)
            offset += c
        stats[k] = per_key_stats
    for s in splits:
        rng.shuffle(s)
    return (splits, stats)

def build_prompt(pair: Dict[str, Any], include_explanation: bool, formatter: PromptFormatter) -> Dict[str, str]:
    instruction = formatter.format_fix_instruction()
    function_name = pair.get('function_name')
    code_slice = pair.get('code_slice')
    annotation = pair.get('annotation') or {}
    fix_analysis = pair.get('fix_analysis') or {}
    if not isinstance(annotation, dict):
        annotation = {}
    annotation['severity'] = None
    solc_version = ''
    export_types = pair.get('_export_vulnerability_types')
    if export_types is None:
        raw_types = pair.get('vulnerability_types') or annotation.get('vulnerability_types') or []
        swc_ids = pair.get('swc_ids') or []
        export_types = map_types_to_8_buckets_or_keep_original(raw_types, swc_ids)
    annotation['vulnerability_types'] = export_types
    input_text = formatter.format_fix_prompt_for_our_models(code_slice, annotation, solc_version, function_name)
    output_parts = ['']
    if include_explanation and fix_analysis:
        output_parts.append('### Analysis\n' + fix_analysis)
    output_parts.append('\n\n### Fixed Code\n' + pair.get('fixed_code', ''))
    output_text = ''.join(output_parts)
    sample_id = f"fix_{pair.get('fix_id') or pair.get('fix_pair_id')}"
    return {'id': sample_id, 'instruction': instruction, 'input': input_text, 'output': output_text}

def save_split(data: List[Dict[str, Any]], path: Path, include_explanation: bool, save_raw: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    formatter = PromptFormatter(include_comments=True)
    with open(path, 'w', encoding='utf-8') as f:
        for pair in data:
            sample = build_prompt(pair, include_explanation, formatter)
            if save_raw:
                sample['raw'] = pair
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')

def _prepare_export_types_in_pairs(pairs: List[Dict[str, Any]]):
    for pair in pairs:
        ann = pair.get('annotation') or {}
        if not isinstance(ann, dict):
            ann = {}
        raw_types = pair.get('vulnerability_types') or ann.get('vulnerability_types') or []
        swc_ids = pair.get('swc_ids') or []
        pair['_export_vulnerability_types'] = map_types_to_8_buckets_or_keep_original(raw_types, swc_ids)

def _compute_bucket_presence_sizes(pairs: List[Dict[str, Any]]) -> Dict[str, int]:
    sizes: Dict[str, int] = {b: 0 for b in BUCKET_ORDER}
    sizes['OTHER'] = 0
    for p in pairs:
        types = _normalize_type_list(p.get('_export_vulnerability_types') or [])
        hits = [t for t in BUCKET_ORDER if t in set(types)]
        if not hits:
            sizes['OTHER'] += 1
        else:
            for h in set(hits):
                sizes[h] += 1
    return sizes

def main():
    args = parse_args()
    (split_names, split_ratios) = resolve_splits_from_args(args)
    random.seed(args.seed)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f'连接数据库: {args.db_path}')
    db = DBManager(args.db_path)
    print('查询修复数据...')
    pairs = fetch_fix_pairs(db=db, only_successful=args.only_successful, min_quality=args.min_quality, dataset_names=args.dataset_names)
    if not pairs:
        print('❌ 未找到符合条件的数据')
        return
    print(f'✅ 获取到 {len(pairs)} 条修复样本')
    _prepare_export_types_in_pairs(pairs)
    bucket_sizes = _compute_bucket_presence_sizes(pairs)
    if args.max_samples:
        rng = random.Random(args.seed)
        rng.shuffle(pairs)
        pairs = pairs[:args.max_samples]
        print(f'下采样: max_samples={args.max_samples}, 实际={len(pairs)}')
    if args.stratify_by_type:
        strat_mode = 'primary'

        def key_fn(p):
            return _bucket_keys_from_display_types(p.get('_export_vulnerability_types') or [], mode=strat_mode, primary_strategy=args.primary_bucket_strategy, bucket_sizes=bucket_sizes)[0]
        (splits, stats) = _stratified_split_dataset(pairs, key_fn=key_fn, split_ratios=split_ratios, seed=args.seed)
        sizes_str = ', '.join([f'{n}={len(splits[i])}' for (i, n) in enumerate(split_names)])
        print(f'划分(分层): {sizes_str}')
        for (i, name) in enumerate(split_names):
            save_split(splits[i], output_dir / f'{name}.jsonl', args.include_explanation, args.save_raw)
        with open(output_dir / 'stratified_split_summary.json', 'w', encoding='utf-8') as f:
            json.dump({'mode': 'stratify_by_type', 'bucket_order': BUCKET_ORDER + ['OTHER'], 'split_names': split_names, 'split_ratios': split_ratios, 'stats_by_bucket': stats, 'primary_bucket_strategy': args.primary_bucket_strategy, 'primary_bucket_presence_sizes': bucket_sizes}, f, indent=2, ensure_ascii=False)
        print(f'🎉 分层导出完成，文件保存在 {output_dir} （详见 stratified_split_summary.json）')
    else:
        splits = split_dataset(pairs, split_ratios=split_ratios, seed=args.seed)
        sizes_str = ', '.join([f'{n}={len(splits[i])}' for (i, n) in enumerate(split_names)])
        print(f'划分: {sizes_str}')
        for (i, name) in enumerate(split_names):
            save_split(splits[i], output_dir / f'{name}.jsonl', args.include_explanation, args.save_raw)
        print(f'🎉 导出完成，文件保存在 {output_dir}')
if __name__ == '__main__':
    main()
