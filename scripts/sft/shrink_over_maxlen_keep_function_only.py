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
\
\
\
   

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Optional, Tuple, List

import numpy as np
from transformers import AutoTokenizer


def normalize_newlines(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


FUNC_RE = re.compile(r"\*\*Function:\*\*\s*([A-Za-z_][A-Za-z0-9_]*)")


def extract_function_name(input_text: str) -> Optional[str]:
    m = FUNC_RE.search(input_text)
    return m.group(1) if m else None


def split_code_slice(input_text: str) -> Tuple[str, Optional[str], str]:
\
\
       
    s = normalize_newlines(input_text)
                                                                               
    m = re.search(r"\*\*Source Code:\*\*", s)
    if m:
        before = s[: m.end()]                             
        rest = s[m.end() :]
    else:
                                                                                       
        marker = "Source Code:"
        i = s.find(marker)
        if i < 0:
            return s, None, ""
        j = i + len(marker)
                                                                   
        if s[j : j + 2] == "**":
            j += 2
        before = s[:j]
        rest = s[j:]

                                                                                    
    end_markers = ["\nPlease provide", "\nOutput ONLY", "\nPlease output", "\nOutput only"]
    end_idx = None
    for em in end_markers:
        j = rest.find(em)
        if j >= 0:
            end_idx = j
            break

    if end_idx is None:
        code = rest
        after = ""
    else:
        code = rest[:end_idx]
        after = rest[end_idx:]

                                                                                                        
    code = code.lstrip("\n")
    return before, code, after


def find_function_span(code: str, func_name: str) -> Optional[Tuple[int, int]]:
\
\
\
       
                                                            
    pat = re.compile(rf"\bfunction\s+{re.escape(func_name)}\s*\(", flags=re.MULTILINE)
    m = pat.search(code)
    if not m:
        return None
    start = m.start()

                                                                                                
    i = m.end()
                                                                                        
    brace_idx = code.find("{", i)
    semi_idx = code.find(";", i)
    if semi_idx != -1 and (brace_idx == -1 or semi_idx < brace_idx):
                                      
        return start, semi_idx + 1
    if brace_idx == -1:
        return None

                                                                                          
    depth = 0
    in_squote = False
    in_dquote = False
    in_line_comment = False
    in_block_comment = False
    esc = False

    k = brace_idx
    n = len(code)
    while k < n:
        ch = code[k]
        nxt = code[k + 1] if k + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            k += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                k += 2
                continue
            k += 1
            continue

        if in_squote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'":
                in_squote = False
            k += 1
            continue

        if in_dquote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_dquote = False
            k += 1
            continue

                        
        if ch == "/" and nxt == "/":
            in_line_comment = True
            k += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            k += 2
            continue

                       
        if ch == "'":
            in_squote = True
            k += 1
            continue
        if ch == '"':
            in_dquote = True
            k += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return start, k + 1
        k += 1
    return None


def build_prompt_full(tok, instruction: str, user_input: str, assistant_output: str) -> str:
    messages_full = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": user_input},
        {"role": "assistant", "content": assistant_output},
    ]
    return tok.apply_chat_template(messages_full, tokenize=False, add_generation_prompt=False)


def token_len(tok, s: str) -> int:
    return len(tok(s, add_special_tokens=False)["input_ids"])


def stats(arr: np.ndarray) -> Dict[str, float]:
    def pct(p: float) -> float:
        return float(np.percentile(arr, p, method="linear"))

    return {
        "min": float(arr.min()),
        "mean": float(arr.mean()),
        "p50": pct(50),
        "p90": pct(90),
        "p95": pct(95),
        "p99": pct(99),
        "max": float(arr.max()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--in_path",
        type=str,
        default="/home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227/sft.jsonl",
    )
    ap.add_argument(
        "--out_path",
        type=str,
        default="/home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227/sft.func_only_over2048.jsonl",
    )
    ap.add_argument(
        "--model_path",
        type=str,
        default="/home/user/zn/models_cache/Qwen2.5-7B-Instruct",
    )
    ap.add_argument("--threshold", type=int, default=2048, help="Apply shrinking if full prompt tokens > threshold")
    ap.add_argument("--max_examples", type=int, default=5, help="Print a few changed ids for sanity.")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tok = AutoTokenizer.from_pretrained(args.model_path, trust_remote_code=True, use_fast=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    try:
        tok.truncation_side = "left"
    except Exception:
        pass

    before_lens: List[int] = []
    after_lens: List[int] = []
    changed = 0
    changed_ids: List[str] = []
    skipped_no_func = 0
    skipped_no_code = 0
    skipped_no_match = 0

    with out_path.open("w", encoding="utf-8") as wf:
        with in_path.open("r", encoding="utf-8") as rf:
            for line_i, line in enumerate(rf, 1):
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                sid = str(item.get("id", f"line{line_i}"))
                instruction = item.get("instruction", "")
                input_text = item.get("input", "")
                output_text = item.get("output", "")

                prompt_before = build_prompt_full(tok, instruction, input_text, output_text)
                lb = token_len(tok, prompt_before)
                before_lens.append(lb)

                new_input = input_text
                if lb > int(args.threshold):
                    func_name = extract_function_name(input_text)
                    if not func_name:
                        skipped_no_func += 1
                    else:
                        before, code, after = split_code_slice(input_text)
                        if code is None:
                            skipped_no_code += 1
                        else:
                            span = find_function_span(code, func_name)
                            if not span:
                                skipped_no_match += 1
                            else:
                                fstart, fend = span
                                func_only = code[fstart:fend].strip()
                                                                       
                                new_input = before.rstrip() + "\n" + func_only + "\n" + after.lstrip("\n")
                                changed += 1
                                if len(changed_ids) < int(args.max_examples):
                                    changed_ids.append(sid)

                prompt_after = build_prompt_full(tok, instruction, new_input, output_text)
                la = token_len(tok, prompt_after)
                after_lens.append(la)

                out_item = dict(item)
                out_item["input"] = new_input
                wf.write(json.dumps(out_item, ensure_ascii=False) + "\n")

    b = np.array(before_lens, dtype=np.int64)
    a = np.array(after_lens, dtype=np.int64)
    sb = stats(b)
    sa = stats(a)
    over_before = int(np.sum(b > int(args.threshold)))
    over_after = int(np.sum(a > int(args.threshold)))

    print(f"wrote: {out_path}")
    print(f"samples: {len(before_lens)}")
    print(f"threshold: {int(args.threshold)}")
    print("")
    print(f"over_threshold BEFORE: {over_before} ({over_before/len(b)*100:.2f}%)")
    print(f"over_threshold AFTER:  {over_after} ({over_after/len(a)*100:.2f}%)")
    print("")
    print("token_len(full_prompt) BEFORE:", {k: (int(v) if k != "mean" else float(v)) for k, v in sb.items()})
    print("token_len(full_prompt) AFTER: ", {k: (int(v) if k != "mean" else float(v)) for k, v in sa.items()})
    print("")
    print(f"changed(over threshold & extracted function): {changed}")
    if changed_ids:
        print("example changed ids:", ", ".join(changed_ids))
    print(f"skipped_no_func: {skipped_no_func}")
    print(f"skipped_no_code: {skipped_no_code}")
    print(f"skipped_no_match: {skipped_no_match}")


if __name__ == "__main__":
    main()


