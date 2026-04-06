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
\
   

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
from transformers import AutoTokenizer


def normalize_newlines(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


HEADING_RE = re.compile(r"^(#{2,4}\s*Fixed Code\s*\n)+", flags=re.IGNORECASE)


def strip_fixed_code_heading(s: str) -> str:
    s2 = normalize_newlines(s).lstrip()
    s2 = HEADING_RE.sub("", s2)
    return s2.lstrip("\n")


def has_fence(s: str) -> bool:
    return "```" in s


def wrap_solidity_codeblock(code: str) -> str:
    code = normalize_newlines(code).strip()
    return f"```solidity\n{code}\n```"


def build_chat_prompt(tok, instruction: str, user_input: str, assistant_output: str) -> str:
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


def iter_jsonl(path: Path) -> Iterable[Dict]:
    with path.open("r", encoding="utf-8") as f:
        for line_i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as e:
                raise ValueError(f"Invalid JSON on line {line_i} in {path}: {e}") from e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--in_path",
        type=str,
        default="/home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227/sft.func_only_over2048.jsonl",
        help="Input JSONL path.",
    )
    ap.add_argument(
        "--out_path",
        type=str,
        default="/home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227/sft.func_only_over2048.codeblock.jsonl",
        help="Output JSONL path.",
    )
    ap.add_argument(
        "--model_path",
        type=str,
        default="/home/user/zn/models_cache/Qwen2.5-7B-Instruct",
        help="Tokenizer path for token stats.",
    )
    ap.add_argument(
        "--threshold",
        type=int,
        default=2048,
        help="Report over-threshold counts for full prompt tokens.",
    )
    ap.add_argument(
        "--language_tag",
        type=str,
        default="solidity",
        help="Fence language tag, e.g. solidity.",
    )
    ap.add_argument("--max_examples", type=int, default=5)
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
    already_fenced = 0

    with out_path.open("w", encoding="utf-8") as wf:
        for item in iter_jsonl(in_path):
            sid = str(item.get("id", ""))
            instruction = item.get("instruction", "")
            input_text = item.get("input", "")
            output_text = item.get("output", "")

            prompt_b = build_chat_prompt(tok, instruction, input_text, output_text)
            before_lens.append(token_len(tok, prompt_b))

            new_output = output_text
            if has_fence(output_text):
                already_fenced += 1
            else:
                code = strip_fixed_code_heading(output_text)
                                            
                code = normalize_newlines(code).strip()
                tag = (args.language_tag or "").strip()
                if tag:
                    new_output = f"```{tag}\n{code}\n```"
                else:
                    new_output = f"```\n{code}\n```"
                changed += 1
                if len(changed_ids) < int(args.max_examples):
                    changed_ids.append(sid)

            prompt_a = build_chat_prompt(tok, instruction, input_text, new_output)
            after_lens.append(token_len(tok, prompt_a))

            out_item = dict(item)
            out_item["output"] = new_output
            wf.write(json.dumps(out_item, ensure_ascii=False) + "\n")

    b = np.array(before_lens, dtype=np.int64)
    a = np.array(after_lens, dtype=np.int64)
    sb = stats(b)
    sa = stats(a)
    over_b = int(np.sum(b > int(args.threshold)))
    over_a = int(np.sum(a > int(args.threshold)))

    print(f"wrote: {out_path}")
    print(f"samples: {len(b)}")
    print(f"already_fenced: {already_fenced}")
    print(f"wrapped_newly: {changed}")
    if changed_ids:
        print("example changed ids:", ", ".join(changed_ids))
    print("")
    print(f"over_threshold>{args.threshold} BEFORE: {over_b} ({over_b/len(b)*100:.2f}%)")
    print(f"over_threshold>{args.threshold} AFTER:  {over_a} ({over_a/len(a)*100:.2f}%)")
    print("")
    print("token_len(full_prompt) BEFORE:", {k: (int(v) if k != "mean" else float(v)) for k, v in sb.items()})
    print("token_len(full_prompt) AFTER: ", {k: (int(v) if k != "mean" else float(v)) for k, v in sa.items()})


if __name__ == "__main__":
    main()









