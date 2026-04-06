#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any, Dict, Tuple

def _strip_nulls_in_dicts(obj: Any) -> Any:
    if isinstance(obj, dict):
        new_obj: Dict[str, Any] = {}
        for (k, v) in obj.items():
            if v is None:
                continue
            new_obj[k] = _strip_nulls_in_dicts(v)
        return new_obj
    if isinstance(obj, list):
        return [_strip_nulls_in_dicts(v) for v in obj]
    return obj

def _process_one_file(path: Path) -> Tuple[bool, int]:
    raw = path.read_text(encoding='utf-8')
    data = json.loads(raw)
    fix = data.get('fix')
    if not isinstance(fix, dict):
        return (False, 0)
    before_fix = fix
    after_fix = _strip_nulls_in_dicts(before_fix)
    if before_fix == after_fix:
        return (False, 0)
    removed = len(before_fix) - len(after_fix)
    data['fix'] = after_fix
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return (True, removed)

def main() -> int:
    parser = argparse.ArgumentParser(description='Remove null-valued fields inside the top-level "fix" object.')
    parser.add_argument('--input', required=True, help='Input .json file or a directory containing .json files.')
    parser.add_argument('--glob', default='*.json', help='Glob pattern when --input is a directory (default: "*.json").')
    parser.add_argument('--output-dir', default=None, help='If set, writes cleaned files to this directory (mirrors filenames).')
    args = parser.parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir) if args.output_dir else None
    if input_path.is_file():
        files = [input_path]
    else:
        files = sorted(input_path.glob(args.glob))
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
    changed_files = 0
    total_removed_keys = 0
    skipped = 0
    for src in files:
        if not src.is_file():
            continue
        if output_dir:
            dst = output_dir / src.name
            dst.write_text(src.read_text(encoding='utf-8'), encoding='utf-8')
            (did_change, removed) = _process_one_file(dst)
        else:
            (did_change, removed) = _process_one_file(src)
        if did_change:
            changed_files += 1
            total_removed_keys += removed
        else:
            skipped += 1
    print(f'done files_total={len(files)} changed={changed_files} skipped={skipped} removed_fix_keys={total_removed_keys}')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
