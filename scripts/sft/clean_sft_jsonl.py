from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
import numpy as np
from transformers import AutoTokenizer
DEFAULT_LONG_INSTRUCTION = 'You are an expert Solidity smart contract security auditor. \nYour task is to fix security vulnerabilities in Solidity code while maintaining functionality. \nProvide the complete fixed function code.\n'
DEFAULT_SHORT_INSTRUCTION = 'You are an expert Solidity smart contract security auditor. Fix vulnerabilities while preserving functionality. Output the complete fixed function code.'

def normalize_newlines(s: str) -> str:
    return s.replace('\r\n', '\n').replace('\r', '\n')

def tabs_to_spaces(s: str, spaces: int=4) -> str:
    return s.replace('\t', ' ' * spaces)

def strip_trailing_ws_per_line(s: str) -> str:
    return '\n'.join((line.rstrip() for line in s.split('\n')))

def collapse_blank_lines(s: str, max_consecutive: int=2) -> str:
    if max_consecutive < 1:
        max_consecutive = 1
    pattern = '\\n{' + str(max_consecutive + 1) + ',}'
    repl = '\n' * max_consecutive
    return re.sub(pattern, repl, s)

def drop_output_heading(s: str) -> str:
    s2 = s.lstrip()
    s2 = re.sub('^(#{2,4}\\s*Fixed Code\\s*\\n)+', '', s2, flags=re.IGNORECASE)
    return s2.lstrip('\n')

def maybe_shorten_instruction(s: str, enable: bool) -> str:
    if not enable:
        return s
    s_norm = normalize_newlines(s).strip()
    default_norm = normalize_newlines(DEFAULT_LONG_INSTRUCTION).strip()
    if s_norm == default_norm:
        return DEFAULT_SHORT_INSTRUCTION
    return s

def clean_text(s: str, *, tab_spaces: int, max_blank_lines: int, drop_fixed_code_heading: bool) -> str:
    s = normalize_newlines(s)
    s = tabs_to_spaces(s, spaces=tab_spaces)
    s = strip_trailing_ws_per_line(s)
    s = collapse_blank_lines(s, max_consecutive=max_blank_lines)
    if drop_fixed_code_heading:
        s = drop_output_heading(s)
    return s

def iter_jsonl(path: Path) -> Iterable[Dict]:
    with path.open('r', encoding='utf-8') as f:
        for (line_i, line) in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as e:
                raise ValueError(f'Invalid JSON on line {line_i} in {path}: {e}') from e

def build_chat_strings(tok, instruction: str, user_input: str, assistant_output: str) -> Tuple[str, str]:
    messages_full = [{'role': 'system', 'content': instruction}, {'role': 'user', 'content': user_input}, {'role': 'assistant', 'content': assistant_output}]
    prompt = tok.apply_chat_template(messages_full, tokenize=False, add_generation_prompt=False)
    messages_prefix = [{'role': 'system', 'content': instruction}, {'role': 'user', 'content': user_input}]
    prefix = tok.apply_chat_template(messages_prefix, tokenize=False, add_generation_prompt=True)
    return (prompt, prefix)

def token_len(tok, s: str) -> int:
    return len(tok(s, add_special_tokens=False)['input_ids'])

def stats(arr: np.ndarray) -> Dict[str, float]:

    def pct(p: float) -> float:
        return float(np.percentile(arr, p, method='linear'))
    return {'min': float(arr.min()), 'mean': float(arr.mean()), 'p50': pct(50), 'p90': pct(90), 'p95': pct(95), 'p99': pct(99), 'max': float(arr.max())}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in_path', type=str, default='/home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227/sft.jsonl')
    ap.add_argument('--out_path', type=str, default='/home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227/sft.cleaned.jsonl')
    ap.add_argument('--model_path', type=str, default='/home/user/zn/models_cache/Qwen2.5-7B-Instruct')
    ap.add_argument('--tab_spaces', type=int, default=4)
    ap.add_argument('--max_blank_lines', type=int, default=2)
    ap.add_argument('--shorten_instruction', action='store_true')
    ap.add_argument('--drop_fixed_code_heading', action='store_true')
    ap.add_argument('--prompt_format', type=str, default='chat', choices=['chat'])
    args = ap.parse_args()
    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tok = AutoTokenizer.from_pretrained(args.model_path, trust_remote_code=True, use_fast=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    try:
        tok.truncation_side = 'left'
    except Exception:
        pass
    before_full: List[int] = []
    after_full: List[int] = []
    n = 0
    with out_path.open('w', encoding='utf-8') as wf:
        for item in iter_jsonl(in_path):
            n += 1
            instruction = item.get('instruction', '')
            input_text = item.get('input', '')
            output_text = item.get('output', '')
            (prompt_b, _) = build_chat_strings(tok, instruction, input_text, output_text)
            before_full.append(token_len(tok, prompt_b))
            instruction2 = maybe_shorten_instruction(instruction, args.shorten_instruction)
            input2 = clean_text(input_text, tab_spaces=int(args.tab_spaces), max_blank_lines=int(args.max_blank_lines), drop_fixed_code_heading=False)
            output2 = clean_text(output_text, tab_spaces=int(args.tab_spaces), max_blank_lines=int(args.max_blank_lines), drop_fixed_code_heading=bool(args.drop_fixed_code_heading))
            (prompt_a, _) = build_chat_strings(tok, instruction2, input2, output2)
            after_full.append(token_len(tok, prompt_a))
            new_item = dict(item)
            new_item['instruction'] = instruction2
            new_item['input'] = input2
            new_item['output'] = output2
            wf.write(json.dumps(new_item, ensure_ascii=False) + '\n')
    b = np.array(before_full, dtype=np.int64)
    a = np.array(after_full, dtype=np.int64)
    sb = stats(b)
    sa = stats(a)
    saved = (b - a).astype(np.int64)
    ss = stats(saved)
    print(f'wrote: {out_path}')
    print(f'samples: {n}')
    print('')
    print('token_len(prompt_full) BEFORE:', {k: int(v) if k != 'mean' else float(v) for (k, v) in sb.items()})
    print('token_len(prompt_full) AFTER: ', {k: int(v) if k != 'mean' else float(v) for (k, v) in sa.items()})
    print('')
    print('tokens_saved (BEFORE-AFTER):', {k: int(v) if k != 'mean' else float(v) for (k, v) in ss.items()})
    print(f'avg_saved_per_sample: {float(saved.mean()):.2f} tokens')
if __name__ == '__main__':
    main()
