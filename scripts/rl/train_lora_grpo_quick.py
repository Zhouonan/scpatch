from __future__ import annotations
import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import torch
import torch.nn.functional as F
from torch.optim import AdamW
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from accelerate import Accelerator
import sys
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))
try:
    from src.tools.slither_manager import SlitherManager
    from src.tools.mythril_manager import MythrilManager
    from src.tools.slice_builder import CodeSliceBuilder
    from src.database.db_manager import DBManager
    from src.database.models import SmartContractFunction
except ImportError:
    print('Warning: Project-specific modules (src.tools/src.database) not found. Mocks may be needed.')
    SlitherManager = None
    MythrilManager = None
    CodeSliceBuilder = None
    DBManager = None
    SmartContractFunction = None
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
except ImportError:
    SentenceTransformer = None
    np = None

def load_jsonl(path: str, limit: Optional[int]=None, seed: int=0) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
            if limit and len(items) >= limit:
                break
    rnd = random.Random(seed)
    rnd.shuffle(items)
    return items

def build_prompt(tok: Any, instruction: str, inp: str, function_name: Optional[str]=None, prompt_format: str='auto') -> str:
    use_chat = False
    if prompt_format == 'chat':
        use_chat = True
    elif prompt_format == 'plain':
        use_chat = False
    else:
        use_chat = hasattr(tok, 'apply_chat_template')
    if use_chat and hasattr(tok, 'apply_chat_template'):
        messages = [{'role': 'system', 'content': instruction}, {'role': 'user', 'content': inp}]
        return tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    return f'Below is an instruction that describes a task, paired with an input that provides further context. Write a response that appropriately completes the request.\n\n### Instruction:\n{instruction}\n\n### Input:\n{inp}\n\n### Response:\n'
_RE_CODE_FENCE = re.compile('```(?:[a-zA-Z0-9_-]+)?\\s*(.*?)\\s*```', re.DOTALL | re.IGNORECASE)

def strip_code_fences(text: str) -> str:
    m = _RE_CODE_FENCE.search(text or '')
    if m:
        return m.group(1).strip()
    return (text or '').strip()

def strip_any_fence_markers(text: str) -> str:
    if not text:
        return ''
    lines = (text or '').splitlines()
    out_lines: List[str] = []
    for ln in lines:
        if ln.strip().startswith('```'):
            continue
        out_lines.append(ln)
    return '\n'.join(out_lines).strip()

def strip_leading_noncode_lines(text: str) -> str:
    if not text:
        return ''
    lines = (text or '').splitlines()

    def is_code_like(s: str) -> bool:
        s = (s or '').strip()
        if not s:
            return False
        if s.startswith(('//', '/*', '*', 'require', 'if', 'for', 'while', 'return', 'emit', 'assert', 'revert', '{', '}', '_')):
            return True
        if s.endswith(('{', '}', ';')):
            return True
        if re.match('^(uint|int|bool|address|bytes|string|mapping)\\b', s):
            return True
        if '=' in s or s.endswith(')') or s.endswith(');'):
            return True
        return False
    start = 0
    while start < len(lines) and (not is_code_like(lines[start])):
        start += 1
    return '\n'.join(lines[start:]).strip()

def extract_fix_id_from_sample_id(sample_id: str) -> Optional[int]:
    m = re.search('fix_(\\d+)', sample_id or '')
    if m:
        return int(m.group(1))
    try:
        return int(sample_id)
    except Exception:
        return None

def _extract_function_block_from_text(text: str, function_name: str) -> Optional[str]:
    cleaned = strip_code_fences(text or '')
    cleaned = strip_any_fence_markers(cleaned)
    if not cleaned:
        return None
    start = cleaned.find(f'function {function_name}')
    if start == -1:
        return None
    brace_open = cleaned.find('{', start)
    if brace_open == -1:
        return None
    i = brace_open
    depth = 0
    while i < len(cleaned):
        ch = cleaned[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return cleaned[start:i + 1].strip()
        i += 1
    return None

def _wrap_body_into_original_function(original_func: str, body_text: str) -> Optional[str]:
    if not original_func:
        return None
    brace_open = original_func.find('{')
    if brace_open == -1:
        return None
    prefix = original_func[:brace_open + 1].rstrip()
    body = strip_code_fences(body_text or '').strip()
    body = strip_any_fence_markers(body)
    body = strip_leading_noncode_lines(body)
    if not body:
        return None
    if body.startswith('{') and body.endswith('}'):
        inner = body[1:-1].strip()
        if inner:
            body = inner
    return f'{prefix}\n{body}\n}}'

def force_input_embeddings_require_grads(model: torch.nn.Module) -> None:
    try:
        emb = model.get_input_embeddings()
    except Exception:
        emb = None
    if emb is None:
        return

    def _hook(_module, _inputs, output):
        try:
            if isinstance(output, torch.Tensor) and (not output.requires_grad):
                output.requires_grad_(True)
        except Exception:
            pass
    try:
        emb.register_forward_hook(_hook)
    except Exception:
        pass

def extract_function_name(inp: str) -> Optional[str]:
    m = re.search('\\*\\*Function:\\*\\*\\s*([A-Za-z_]\\w*)', inp)
    if m:
        return m.group(1).strip()
    return None

def extract_contract_source(inp: str) -> Optional[str]:
    if not inp:
        return None
    marker = '**Source Code:**'
    if marker not in inp:
        return None
    after = inp.split(marker, 1)[1]
    tail = 'Please provide the complete fixed version'
    if tail in after:
        after = after.split(tail, 1)[0]
    return after.strip()

def extract_original_function(contract: str, function_name: str) -> Optional[str]:
    start = contract.find(f'function {function_name}')
    if start == -1:
        return None
    brace_open = contract.find('{', start)
    if brace_open == -1:
        return None
    i = brace_open
    depth = 0
    while i < len(contract):
        ch = contract[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return contract[start:i + 1].strip()
        i += 1
    return None

def replace_function_in_contract(contract: str, function_name: str, new_function_code: str) -> Optional[str]:
    start = contract.find(f'function {function_name}')
    if start == -1:
        return None
    brace_open = contract.find('{', start)
    if brace_open == -1:
        return None
    i = brace_open
    depth = 0
    while i < len(contract):
        ch = contract[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                return contract[:start] + new_function_code.strip() + contract[end:]
        i += 1
    return None

@dataclass
class VerifyResult:
    compiles: bool
    slither_passed: bool
    slither_issue_count: int
    slither_issues: List[str]
    slither_error: Optional[str]
    mythril_passed: bool
    mythril_issue_count: int
    mythril_issues: List[str]
    mythril_error: Optional[str]

    @property
    def issue_count(self) -> int:
        return int(self.slither_issue_count + self.mythril_issue_count)

    @property
    def issues(self) -> List[str]:
        return list(self.slither_issues) + list(self.mythril_issues)

    @property
    def error(self) -> Optional[str]:
        return self.slither_error or self.mythril_error

def _truncate_lines(s: str, max_lines: int=30, max_chars: int=4000) -> str:
    s = (s or '').strip()
    if not s:
        return ''
    lines = s.splitlines()
    out = '\n'.join(lines[:max_lines])
    if len(out) > max_chars:
        out = out[:max_chars] + '\n...<truncated>...'
    if len(lines) > max_lines:
        out = out + f'\n...<truncated {len(lines) - max_lines} lines>...'
    return out

def compile_contract(slither_mgr: Any, contract_src: str, verbose: bool=False, debug: bool=False, debug_save_dir: Optional[Path]=None, tag: str='') -> Tuple[bool, Optional[str], Optional[str]]:
    (fd, tmp) = tempfile.mkstemp(suffix='.sol')
    os.close(fd)
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(contract_src)
        solc_path = slither_mgr.setup_solc_version(tmp)
        if not solc_path:
            return (False, 'solc version setup failed (missing pragma or solcx unavailable)', None)
        if solc_path == 'SOLCX_ENV':
            try:
                import solcx
                pragma_v = getattr(slither_mgr, 'extract_solidity_version', lambda _: None)(tmp)
                feat_v = getattr(slither_mgr, 'detect_required_features', lambda _: None)(tmp)

                def _vt(v: str) -> Tuple[int, int, int]:
                    (a, b, c) = (v.split('.') + ['0', '0', '0'])[:3]
                    return (int(a), int(b), int(c))
                required_v = None
                if pragma_v and feat_v:
                    required_v = pragma_v if _vt(pragma_v) >= _vt(feat_v) else feat_v
                else:
                    required_v = pragma_v or feat_v
                if not required_v:
                    return (False, 'cannot infer solidity version (no pragma found)', None)
                candidate_versions = [required_v]
                if hasattr(slither_mgr, 'find_compatible_version'):
                    try:
                        compat = slither_mgr.find_compatible_version(required_v)
                        if compat and compat not in candidate_versions:
                            candidate_versions.append(compat)
                    except Exception:
                        pass
                resolved = None
                for v in candidate_versions:
                    try:
                        if hasattr(solcx, 'install') and hasattr(solcx.install, 'get_executable'):
                            p = solcx.install.get_executable(v)
                            if p and os.path.exists(str(p)):
                                resolved = str(p)
                                break
                    except Exception:
                        continue
                if not resolved:
                    return (False, f'failed to resolve solc executable via solcx for version={required_v}', None)
                solc_path = resolved
            except Exception as e:
                return (False, f'failed to resolve solc via solcx (SOLCX_ENV): {e}', None)
        try:
            out = subprocess.run([solc_path, '--bin', tmp], capture_output=True, text=True, timeout=40)
        except FileNotFoundError:
            return (False, 'solc not found', None)
        except subprocess.TimeoutExpired:
            return (False, 'compile timeout', None)
        if out.returncode == 0:
            return (True, None, solc_path)
        err = out.stderr.strip() or out.stdout.strip() or 'compile failed (no stderr/stdout)'
        if verbose or debug:
            t = f' tag={tag}' if tag else ''
            print(f'[compile]{t} solc={solc_path} rc={out.returncode} file={tmp}')
            if out.stderr:
                print('[compile] stderr:\n' + _truncate_lines(out.stderr))
            if debug and out.stdout:
                print('[compile] stdout:\n' + _truncate_lines(out.stdout))
        if debug and debug_save_dir is not None:
            try:
                debug_save_dir.mkdir(parents=True, exist_ok=True)
                name = f"compile_fail{('_' + tag if tag else '')}_{Path(tmp).stem}.sol"
                (debug_save_dir / name).write_text(contract_src, encoding='utf-8')
            except Exception:
                pass
        return (False, err, solc_path)
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

def slither_check(slither_mgr: Any, contract_src: str, verbose: bool=False, debug: bool=False, debug_save_dir: Optional[Path]=None, tag: str='') -> Tuple[bool, int, List[str], Optional[str]]:
    (fd, tmp) = tempfile.mkstemp(suffix='.sol')
    os.close(fd)
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(contract_src)
        issues: List[str] = []
        with slither_mgr.analyze_contract(tmp) as slither:
            if not slither:
                return (True, 0, [], None)
            for detector in slither.detectors:
                if not hasattr(detector, 'results'):
                    continue
                for res in detector.results:
                    severity = getattr(res, 'severity', None)
                    if severity in ['High', 'Medium']:
                        desc = getattr(res, 'description', '')
                        check_name = getattr(res, 'check', getattr(detector, 'ARGUMENT', 'UnknownCheck'))
                        issues.append(f'{check_name}: {desc}')
        passed = len(issues) == 0
        if debug:
            t = f' tag={tag}' if tag else ''
            print(f'[slither]{t} passed={passed} issues={len(issues)} file={tmp}')
            if issues:
                print('[slither] issues:\n' + _truncate_lines('\n'.join(issues), max_lines=20))
        if debug and (not passed) and (debug_save_dir is not None):
            try:
                debug_save_dir.mkdir(parents=True, exist_ok=True)
                name = f"slither_fail{('_' + tag if tag else '')}_{Path(tmp).stem}.sol"
                (debug_save_dir / name).write_text(contract_src, encoding='utf-8')
            except Exception:
                pass
        return (passed, len(issues), issues, None)
    except Exception as e:
        if verbose:
            print(f'[slither] error: {e}')
        return (True, 0, [], str(e))
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

def mythril_check(mythril_mgr: Any, contract_src: str, timeout: int=120, severities: Optional[Iterable[str]]=('high', 'medium'), max_issues: int=50, verbose: bool=False, debug: bool=False, debug_save_dir: Optional[Path]=None, tag: str='') -> Tuple[bool, int, List[str], Optional[str]]:
    res = mythril_mgr.analyze_source(contract_src, timeout=timeout, severities=severities, max_issues=max_issues)
    passed = bool(res.passed)
    issues = list(res.issues or [])
    err = res.error
    if debug:
        t = f' tag={tag}' if tag else ''
        print(f"[mythril]{t} passed={passed} issues={len(issues)} err={(err or '')[:160]}")
        if issues:
            print('[mythril] issues:\n' + _truncate_lines('\n'.join(issues), max_lines=20))
    if debug and (not passed) and (debug_save_dir is not None):
        try:
            debug_save_dir.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha1((contract_src or '').encode('utf-8', errors='ignore')).hexdigest()[:10]
            name = f"mythril_fail{('_' + tag if tag else '')}_{h}.sol"
            (debug_save_dir / name).write_text(contract_src, encoding='utf-8')
        except Exception:
            pass
    if verbose and err:
        print(f'[mythril] note: {err}')
    return (passed, len(issues), issues, err)

def diff_penalty(a: str, b: str) -> float:
    import difflib
    a = a or ''
    b = b or ''
    r = difflib.SequenceMatcher(a=a, b=b).ratio()
    return float(1.0 - r)

def function_reward(encoder: Optional[Any], original_func: str, new_func: str, w_embed: float, w_edit: float) -> float:
    if not original_func or not new_func:
        return 0.0
    r = 0.0
    if encoder is not None and np is not None:
        ea = encoder.encode([original_func], normalize_embeddings=True)
        eb = encoder.encode([new_func], normalize_embeddings=True)
        sim = float((ea * eb).sum())
        r += w_embed * sim
    r -= w_edit * diff_penalty(original_func, new_func)
    return float(r)

def _gather_logprobs(logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
    logp = F.log_softmax(logits, dim=-1)
    return logp.gather(-1, labels.unsqueeze(-1)).squeeze(-1)

@torch.no_grad()
def compute_sequence_logprob(model: torch.nn.Module, input_ids: torch.Tensor, gen_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
    full = torch.cat([input_ids, gen_ids], dim=1)
    full_mask = torch.cat([attention_mask, torch.ones_like(gen_ids)], dim=1)
    out = model(input_ids=full, attention_mask=full_mask, use_cache=False)
    logits = out.logits
    L = input_ids.shape[1]
    G = gen_ids.shape[1]
    pred_logits = logits[:, L - 1:L + G - 1, :]
    lp = _gather_logprobs(pred_logits, gen_ids)
    return lp.sum(dim=1)

def sha1_text(s: str) -> str:
    return hashlib.sha1((s or '').encode('utf-8', errors='ignore')).hexdigest()

def run_staggered_load(accelerator: Accelerator, enabled: bool, fn, *, group_size: int=1, sleep_s: float=0.0) -> Any:
    if not enabled or accelerator.num_processes <= 1:
        return fn()
    g = max(1, int(group_size))
    out: Any = None
    for start in range(0, accelerator.num_processes, g):
        end = min(accelerator.num_processes, start + g)
        active = start <= accelerator.process_index < end
        if active:
            out = fn()
        if sleep_s and sleep_s > 0:
            time.sleep(float(sleep_s))
        accelerator.wait_for_everyone()
    if out is None:
        raise RuntimeError('staggered load did not run on this process (unexpected).')
    return out

def main():
    parser = argparse.ArgumentParser(description='Quick GRPO-style RL for LoRA repair model (compile+slither constraint).')
    parser.add_argument('--train-jsonl', type=str, required=True, help='Training JSONL (fix_sft format)')
    parser.add_argument('--limit', type=int, default=400, help='Max samples for quick run (e.g., 200-500)')
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--base-model', type=str, required=True, help='Base HF model path/name')
    parser.add_argument('--sft-lora', type=str, required=True, help='SFT LoRA checkpoint dir')
    parser.add_argument('--ref-on-cpu', action='store_true', help='Load reference model on CPU')
    parser.add_argument('--db-path', type=str, default=None)
    parser.add_argument('--use-db-contract', action='store_true')
    parser.add_argument('--prompt-format', type=str, default='auto', choices=['auto', 'plain', 'chat'])
    parser.add_argument('--dtype', type=str, default='auto', choices=['auto', 'fp16', 'bf16', 'fp32'])
    parser.add_argument('--gradient-checkpointing', action='store_true')
    parser.add_argument('--debug-verify', action='store_true')
    parser.add_argument('--debug-save-contracts', action='store_true')
    parser.add_argument('--mythril', action='store_true')
    parser.add_argument('--mythril-timeout', type=int, default=120)
    parser.add_argument('--mythril-severities', type=str, default='high,medium')
    parser.add_argument('--mythril-max-issues', type=int, default=50)
    parser.add_argument('--max-prompt-len', type=int, default=2048)
    parser.add_argument('--max-new-tokens', type=int, default=512)
    parser.add_argument('--temperature', type=float, default=0.7)
    parser.add_argument('--top-p', type=float, default=0.9)
    parser.add_argument('--k', type=int, default=4, help='Candidates per prompt (K)')
    parser.add_argument('--gen-microbatch', type=int, default=1)
    parser.add_argument('--batch-prompts', type=int, default=1)
    parser.add_argument('--lr', type=float, default=1e-05)
    parser.add_argument('--steps', type=int, default=50)
    parser.add_argument('--grad-accum', type=int, default=1)
    parser.add_argument('--w-stmt', type=float, default=0.8)
    parser.add_argument('--w-func-embed', type=float, default=0.3)
    parser.add_argument('--w-func-edit', type=float, default=0.2)
    parser.add_argument('--kl-beta', type=float, default=0.01)
    parser.add_argument('--success-bonus', type=float, default=1.0)
    parser.add_argument('--compile-only-bonus', type=float, default=0.1)
    parser.add_argument('--epsilon-cost', type=float, default=0.5)
    parser.add_argument('--lambda-init', type=float, default=0.0)
    parser.add_argument('--lambda-lr', type=float, default=0.05)
    parser.add_argument('--out-dir', type=str, default='results/rl_lora_quick')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--stagger-load', action='store_true')
    parser.add_argument('--stagger-load-group-size', type=int, default=1)
    parser.add_argument('--stagger-load-sleep', type=float, default=0.0)
    args = parser.parse_args()
    accelerator = Accelerator()
    random.seed(args.seed + accelerator.process_index)
    torch.manual_seed(args.seed + accelerator.process_index)
    out_dir = Path(args.out_dir)
    if accelerator.is_main_process:
        out_dir.mkdir(parents=True, exist_ok=True)
    accelerator.wait_for_everyone()
    log_path = out_dir / 'train_log.jsonl'
    debug_save_dir = out_dir / 'debug_contracts' if args.debug_verify and args.debug_save_contracts else None
    db_session = None
    if args.use_db_contract:
        if not args.db_path or DBManager is None:
            raise ValueError('--use-db-contract requires --db-path and DBManager module')
        db_session = DBManager(args.db_path).get_session()
    slice_builder = CodeSliceBuilder(include_comments=bool(args.verbose)) if CodeSliceBuilder else None
    db_cache: Dict[int, Any] = {}
    data = load_jsonl(args.train_jsonl, limit=args.limit, seed=args.seed)
    if not data:
        raise RuntimeError('No data loaded.')
    tok = run_staggered_load(accelerator, enabled=bool(args.stagger_load), group_size=int(args.stagger_load_group_size), sleep_s=float(args.stagger_load_sleep), fn=lambda : AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True))
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token
    try:
        tok.truncation_side = 'left'
    except Exception:
        pass

    def _resolve_dtype() -> torch.dtype:
        if args.dtype == 'fp16':
            return torch.float16
        if args.dtype == 'bf16':
            return torch.bfloat16
        if args.dtype == 'fp32':
            return torch.float32
        mp = str(accelerator.mixed_precision or 'no').lower()
        if mp == 'fp16':
            return torch.float16
        if mp == 'bf16':
            return torch.bfloat16
        if accelerator.device.type == 'cuda':
            try:
                if torch.cuda.is_bf16_supported():
                    return torch.bfloat16
            except Exception:
                pass
            return torch.float16
        return torch.float32
    dtype = _resolve_dtype()
    policy_base = run_staggered_load(accelerator, enabled=bool(args.stagger_load), group_size=int(args.stagger_load_group_size), sleep_s=float(args.stagger_load_sleep), fn=lambda : AutoModelForCausalLM.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=dtype, device_map=None, low_cpu_mem_usage=True))
    if args.gradient_checkpointing:
        policy_base.gradient_checkpointing_enable()
        try:
            policy_base.enable_input_require_grads()
        except Exception:
            pass
        policy_base.config.use_cache = False
    policy_base.to(accelerator.device)
    policy = run_staggered_load(accelerator, enabled=bool(args.stagger_load), group_size=int(args.stagger_load_group_size), sleep_s=float(args.stagger_load_sleep), fn=lambda : PeftModel.from_pretrained(policy_base, args.sft_lora, is_trainable=True))
    policy.train()
    if args.gradient_checkpointing:
        force_input_embeddings_require_grads(policy)
    ref_device = 'cpu' if args.ref_on_cpu else str(accelerator.device)
    ref_base = run_staggered_load(accelerator, enabled=bool(args.stagger_load), group_size=int(args.stagger_load_group_size), sleep_s=float(args.stagger_load_sleep), fn=lambda : AutoModelForCausalLM.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=torch.float32 if ref_device == 'cpu' else dtype, device_map=None, low_cpu_mem_usage=True))
    ref_base.to(ref_device)
    ref = run_staggered_load(accelerator, enabled=bool(args.stagger_load), group_size=int(args.stagger_load_group_size), sleep_s=float(args.stagger_load_sleep), fn=lambda : PeftModel.from_pretrained(ref_base, args.sft_lora).to(ref_device))
    ref.eval()
    for p in ref.parameters():
        p.requires_grad_(False)
    trainable_params = [p for p in policy.parameters() if p.requires_grad]
    if not trainable_params:
        raise RuntimeError('No trainable parameters found in LoRA.')
    opt = AdamW(trainable_params, lr=args.lr)
    (policy, opt) = accelerator.prepare(policy, opt)
    slither_mgr = SlitherManager(debug=args.verbose) if SlitherManager else None
    mythril_mgr = MythrilManager(debug=args.verbose) if args.mythril and MythrilManager else None
    mythril_severities = tuple([s.strip().lower() for s in str(args.mythril_severities).split(',') if s.strip()])
    encoder = None
    if SentenceTransformer:
        try:
            encoder = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
        except Exception:
            pass
    verify_cache: Dict[str, VerifyResult] = {}
    lagrange_lambda = float(args.lambda_init)
    idx = accelerator.process_index
    log_f = open(log_path, 'a', encoding='utf-8') if accelerator.is_main_process else None
    try:
        for step in range(1, args.steps + 1):
            if accelerator.is_main_process:
                print(f'[step {step}] start', flush=True)
            batch_items = []
            for _ in range(args.batch_prompts):
                batch_items.append(data[idx % len(data)])
                idx += accelerator.num_processes
            total_loss = 0.0
            batch_costs: List[float] = []
            batch_rewards: List[float] = []
            batch_success: List[int] = []
            opt.zero_grad(set_to_none=True)
            for item in batch_items:
                instruction = item.get('instruction', '')
                inp = item.get('input', '')
                sample_id = item.get('id', 'unknown')
                func_name = extract_function_name(inp)
                contract = extract_contract_source(inp)
                if not func_name:
                    continue
                func_data_for_validation = None
                orig_func = ''
                if args.use_db_contract and db_session:
                    fix_id = extract_fix_id_from_sample_id(str(sample_id))
                    if fix_id is not None:
                        if fix_id not in db_cache:
                            db_cache[fix_id] = db_session.query(SmartContractFunction).filter(SmartContractFunction.id == fix_id).first()
                        row = db_cache.get(fix_id)
                        if row:
                            func_data_for_validation = {'function_name': row.function_name, 'function_code': row.function_code, 'solidity_version': row.solidity_version or '0.8.0', 'contract_path': row.contract_path}
                            orig_func = (row.function_code or '').strip()
                if not orig_func:
                    if not contract:
                        continue
                    orig_func = extract_original_function(contract, func_name) or ''
                prompt = build_prompt(tok, instruction, inp, function_name=func_name, prompt_format=args.prompt_format)
                enc = tok(prompt, return_tensors='pt', truncation=True, max_length=args.max_prompt_len)
                input_ids = enc['input_ids'].to(accelerator.device)
                attn = enc['attention_mask'].to(accelerator.device)
                cand_texts: List[str] = []
                cand_ids: List[torch.Tensor] = []
                was_training = policy.training
                policy.eval()
                with torch.no_grad():
                    gen_model = accelerator.unwrap_model(policy)
                    remaining = int(args.k)
                    gen_mb = max(1, getattr(args, 'gen_microbatch', 1))
                    while remaining > 0:
                        cur = min(gen_mb, remaining)
                        b_input_ids = input_ids.expand(cur, -1).contiguous()
                        b_attn = attn.expand(cur, -1).contiguous()
                        out = gen_model.generate(input_ids=b_input_ids, attention_mask=b_attn, max_new_tokens=args.max_new_tokens, do_sample=True, temperature=args.temperature, top_p=args.top_p, pad_token_id=tok.pad_token_id, eos_token_id=tok.eos_token_id, use_cache=True)
                        gen = out[:, input_ids.shape[1]:]
                        for i in range(gen.shape[0]):
                            txt = tok.decode(gen[i], skip_special_tokens=True)
                            cand_texts.append(strip_code_fences(txt))
                            cand_ids.append(gen[i:i + 1, :])
                        remaining -= cur
                if was_training:
                    policy.train()
                scores: List[float] = []
                logps: List[torch.Tensor] = []
                for (cand_i, (gen_ids, gen_txt)) in enumerate(zip(cand_ids, cand_texts)):
                    cand_tag = f'{sample_id}_{func_name}_k{cand_i}'
                    fixed_func = _extract_function_block_from_text(gen_txt, func_name)
                    if not fixed_func:
                        fixed_func = _wrap_body_into_original_function(orig_func, gen_txt)
                    new_func_for_reward = fixed_func or ''
                    vr = None
                    if not fixed_func:
                        vr = VerifyResult(False, False, 0, [], 'extract_fail', True, 0, [], None)
                    else:
                        repaired = None
                        if func_data_for_validation and slice_builder:
                            rebuilt = slice_builder.rebuild_full_contract(func_data_for_validation, fixed_func)
                            repaired = rebuilt if rebuilt else slice_builder.build_simplified_contract(func_data_for_validation, fixed_code=fixed_func)
                        elif contract:
                            repaired = replace_function_in_contract(contract, func_name, fixed_func)
                        if not repaired:
                            vr = VerifyResult(False, False, 0, [], 'replace_fail', True, 0, [], None)
                        else:
                            vkey = sha1_text(repaired)
                            if vkey in verify_cache:
                                vr = verify_cache[vkey]
                            else:
                                (ok, cerr, _) = compile_contract(slither_mgr, repaired, debug=args.debug_verify, debug_save_dir=debug_save_dir, tag=cand_tag) if slither_mgr else (False, 'no_mgr', None)
                                if not ok:
                                    vr = VerifyResult(False, False, 0, [], cerr, True, 0, [], None)
                                else:
                                    (sp, ic, issues, serr) = slither_check(slither_mgr, repaired, debug=args.debug_verify, debug_save_dir=debug_save_dir, tag=cand_tag)
                                    (mp, mic, missues, merr) = (True, 0, [], None)
                                    if mythril_mgr:
                                        (mp, mic, missues, merr) = mythril_check(mythril_mgr, repaired, timeout=args.mythril_timeout, severities=mythril_severities, debug=args.debug_verify, debug_save_dir=debug_save_dir, tag=cand_tag)
                                    vr = VerifyResult(True, sp, ic, issues, serr, mp, mic, missues, merr)
                                verify_cache[vkey] = vr
                    if not vr.compiles:
                        cost = 5.0
                    elif not vr.slither_passed or (args.mythril and (not vr.mythril_passed)):
                        cost = float(max(1, vr.issue_count))
                    else:
                        cost = 0.0
                    r_stmt = args.w_stmt * (1.0 if vr.compiles else 0.0)
                    r_func = function_reward(encoder, orig_func, new_func_for_reward, args.w_func_embed, args.w_func_edit)
                    ok_security = vr.slither_passed and (vr.mythril_passed if args.mythril else True)
                    if vr.compiles and ok_security:
                        r_ver = args.success_bonus
                        success = 1
                    elif vr.compiles:
                        r_ver = args.compile_only_bonus
                        success = 0
                    else:
                        r_ver = 0.0
                        success = 0
                    gen_ids_on_ref = gen_ids.to(ref_device)
                    ref_lp = compute_sequence_logprob(ref, input_ids.to(ref_device), gen_ids_on_ref, attn.to(ref_device))
                    gen_ids_on_policy = gen_ids.to(accelerator.device)
                    policy_out = policy(input_ids=torch.cat([input_ids, gen_ids_on_policy], dim=1), attention_mask=torch.cat([attn, torch.ones_like(gen_ids_on_policy)], dim=1), use_cache=False)
                    L = input_ids.shape[1]
                    G = gen_ids_on_policy.shape[1]
                    pred_logits = policy_out.logits[:, L - 1:L + G - 1, :].contiguous()
                    pol_lp = _gather_logprobs(pred_logits, gen_ids_on_policy).sum(dim=1)
                    del policy_out, pred_logits
                    kl_approx = (pol_lp - ref_lp.to(pol_lp.device)) / max(1.0, float(G))
                    r_tok = -args.kl_beta * float(kl_approx.item())
                    total_r = float(r_stmt + r_func + r_ver + r_tok)
                    score = total_r - lagrange_lambda * cost
                    scores.append(score)
                    logps.append(pol_lp.squeeze(0))
                    batch_costs.append(cost)
                    batch_rewards.append(total_r)
                    batch_success.append(success)
                if not scores:
                    continue
                baseline = sum(scores) / len(scores)
                adv = torch.tensor([s - baseline for s in scores], dtype=torch.float32, device=accelerator.device)
                logp_stack = torch.stack(logps, dim=0).to(accelerator.device)
                loss = -(adv.detach() * logp_stack).mean()
                loss = loss / max(1, args.grad_accum)
                accelerator.backward(loss)
                total_loss += float(loss.item())
            accelerator.clip_grad_norm_([p for p in policy.parameters() if p.requires_grad], max_norm=1.0)
            opt.step()
            avg_reward = float(sum(batch_rewards) / max(1, len(batch_rewards))) if batch_rewards else 0.0
            succ_rate = float(sum(batch_success) / max(1, len(batch_success))) if batch_success else 0.0
            avg_cost = float(sum(batch_costs) / max(1, len(batch_costs))) if batch_costs else 0.0
            t_cost = torch.tensor(avg_cost, device=accelerator.device)
            g_cost = float(accelerator.reduce(t_cost, reduction='mean').item())
            lagrange_lambda = max(0.0, lagrange_lambda + args.lambda_lr * (g_cost - args.epsilon_cost))
            if accelerator.is_main_process:
                print(f'[step {step}] reward={avg_reward:.3f} cost={g_cost:.3f} succ={succ_rate:.2%} lambda={lagrange_lambda:.3f}')
                if log_f:
                    log_f.write(json.dumps({'step': step, 'reward': avg_reward, 'cost': g_cost, 'lambda': lagrange_lambda, 'loss': total_loss}) + '\n')
                    log_f.flush()
            accelerator.wait_for_everyone()
        if accelerator.is_main_process:
            save_dir = out_dir / 'rl_lora'
            save_dir.mkdir(parents=True, exist_ok=True)
            accelerator.unwrap_model(policy).save_pretrained(str(save_dir))
            tok.save_pretrained(str(save_dir))
            print(f'Saved to {save_dir}')
    finally:
        if log_f:
            log_f.close()
        if db_session:
            try:
                db_session.close()
            except:
                pass
if __name__ == '__main__':
    main()
