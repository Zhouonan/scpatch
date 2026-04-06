from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import random
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import torch
import torch.distributed as dist
import torch.nn.functional as F
import torch.nn as nn
from torch.optim import AdamW
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import sys
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))
try:
    from src.tools.slither_manager import SlitherManager
    from src.tools.mythril_manager import MythrilManager
    from src.tools.slither_utils import collect_slither_issues
    from src.tools.code_similarity import text_similarity
    from src.tools.slice_builder import CodeSliceBuilder
    from src.database.db_manager import DBManager
    from src.database.models import SmartContractFunction
except ImportError:
    print('Warning: Project-specific modules (src.tools/src.database) not found. Mocks may be needed.')
    SlitherManager = None
    MythrilManager = None
    collect_slither_issues = None
    text_similarity = None
    CodeSliceBuilder = None
    DBManager = None
    SmartContractFunction = None
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
except ImportError:
    SentenceTransformer = None
    np = None
try:
    from src.tools.rag_retriever import HybridRetriever, RAGPromptBuilder, build_documents_from_fix_sft_jsonl, parse_vuln_info_from_text
except Exception:
    HybridRetriever = None
    RAGPromptBuilder = None
    build_documents_from_fix_sft_jsonl = None
    parse_vuln_info_from_text = None

class _Timer:
    __slots__ = ('_t0',)

    def __init__(self) -> None:
        self._t0 = 0.0

    def start(self) -> None:
        self._t0 = time.time()

    def stop(self) -> float:
        return float(time.time() - self._t0)

def _maybe_cuda_sync(device: torch.device, enabled: bool) -> None:
    if not enabled:
        return
    if device.type == 'cuda':
        try:
            torch.cuda.synchronize(device)
        except Exception:
            pass

def _ts() -> str:
    return time.strftime('%H:%M:%S', time.localtime())

def _dprint(enabled: bool, rank: int, msg: str) -> None:
    if not enabled:
        return
    print(f'[{_ts()}][rank{rank}] {msg}', flush=True)

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

def _clip(s: str, max_chars: int) -> str:
    s = s or ''
    try:
        max_chars = int(max_chars)
    except Exception:
        max_chars = 2000
    if max_chars <= 0 or len(s) <= max_chars:
        return s
    return s[:max_chars] + '\n...<truncated>...'

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

def _gate_features(inp: str) -> torch.Tensor:
    text = inp or ''
    low = text.lower()
    code_len = float(len(text))
    has_call = 1.0 if 'delegatecall' in low or '.call' in low or 'call.value' in low else 0.0
    has_tx_origin = 1.0 if 'tx.origin' in low else 0.0
    has_transfer = 1.0 if '.transfer(' in low or '.send(' in low else 0.0
    has_require = 1.0 if 'require(' in low else 0.0
    has_reentrancy = 1.0 if 'reentr' in low else 0.0
    has_overflow = 1.0 if 'overflow' in low or 'underflow' in low else 0.0
    has_access = 1.0 if 'onlyowner' in low or 'access control' in low else 0.0
    has_random = 1.0 if 'random' in low or 'blockhash' in low or 'block.timestamp' in low else 0.0
    code_len_n = min(1.0, code_len / 6000.0)
    return torch.tensor([code_len_n, has_call, has_tx_origin, has_transfer, has_require, has_reentrancy, has_overflow, has_access, has_random, 1.0], dtype=torch.float32)

class RagGatePolicy(nn.Module):

    def __init__(self, obs_dim: int=10, hidden: int=64):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(obs_dim, hidden), nn.Tanh(), nn.Linear(hidden, hidden), nn.Tanh(), nn.Linear(hidden, 2))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

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
                return (False, 0, [], 'slither_none')
            try:
                if hasattr(slither, 'run_detectors'):
                    slither.run_detectors()
            except Exception:
                pass
            if collect_slither_issues is not None:
                issues.extend(collect_slither_issues(slither, severities=('high', 'medium', 'low')))
            else:
                for detector in slither.detectors:
                    if not hasattr(detector, 'results'):
                        continue
                    for res in detector.results:
                        sev = getattr(res, 'severity', None)
                        if sev is None:
                            sev = getattr(res, 'impact', None)
                        sev_s = str(sev).lower() if sev is not None else ''
                        if sev_s in ('high', 'medium', 'low'):
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
        return (False, 0, [], str(e))
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

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)

def dist_info() -> Tuple[int, int, int]:
    rank = _env_int('RANK', 0)
    world_size = _env_int('WORLD_SIZE', 1)
    local_rank = _env_int('LOCAL_RANK', 0)
    return (rank, local_rank, world_size)

def init_dist_if_needed() -> Tuple[int, int, int]:
    (rank, local_rank, world_size) = dist_info()
    if world_size > 1:
        if not dist.is_available():
            raise RuntimeError('torch.distributed not available')
        if not dist.is_initialized():
            dist.init_process_group(backend='nccl', device_id=int(local_rank))
        torch.cuda.set_device(local_rank)
    elif torch.cuda.is_available():
        torch.cuda.set_device(0)
    return (rank, local_rank, world_size)

def _make_groups(world_size: int, num_policy_ranks: int, *, ref_mode: str, rank: int) -> Tuple[Optional[dist.ProcessGroup], Optional[dist.ProcessGroup], Optional[dist.ProcessGroup]]:
    if world_size <= 1:
        return (None, None, None)
    policy_ranks = list(range(num_policy_ranks))
    ref_ranks = list(range(num_policy_ranks, world_size))
    pg_policy = dist.new_group(ranks=policy_ranks)
    pg_ref = dist.new_group(ranks=ref_ranks) if ref_ranks else None
    pg_pair = None
    if ref_mode == 'paired' and world_size in (2, 4):
        if rank < num_policy_ranks:
            pair_ranks = [rank, rank + num_policy_ranks]
        else:
            pair_ranks = [rank - num_policy_ranks, rank]
        pg_pair = dist.new_group(ranks=pair_ranks)
    return (pg_policy, pg_ref, pg_pair)

def paired_ref_request(*, peer_rank: int, input_ids: torch.Tensor, attention_mask: torch.Tensor, gen_ids: torch.Tensor, pair_group: Optional[dist.ProcessGroup]=None) -> torch.Tensor:
    out = paired_ref_request_batch(peer_rank=peer_rank, input_ids=input_ids, attention_mask=attention_mask, gen_ids_batch=gen_ids, pair_group=pair_group)
    return out.view(1)

def paired_ref_request_batch(*, peer_rank: int, input_ids: torch.Tensor, attention_mask: torch.Tensor, gen_ids_batch: torch.Tensor, pair_group: Optional[dist.ProcessGroup]=None) -> torch.Tensor:
    assert input_ids.ndim == 2 and attention_mask.ndim == 2 and (gen_ids_batch.ndim == 2)
    assert input_ids.shape[0] == 1 and attention_mask.shape[0] == 1
    B = int(gen_ids_batch.shape[0])
    L = int(input_ids.shape[1])
    G = int(gen_ids_batch.shape[1])
    hdr = torch.tensor([B, L, G], device=input_ids.device, dtype=torch.long)
    if pair_group is not None:
        dist.send(hdr, group=pair_group, group_dst=1)
        dist.send(input_ids.to(dtype=torch.long), group=pair_group, group_dst=1)
        dist.send(attention_mask.to(dtype=torch.long), group=pair_group, group_dst=1)
        dist.send(gen_ids_batch.to(dtype=torch.long), group=pair_group, group_dst=1)
        out = torch.empty((B,), device=input_ids.device, dtype=torch.float32)
        dist.recv(out, group=pair_group, group_src=1)
        return out
    dist.send(hdr, dst=peer_rank)
    dist.send(input_ids.to(dtype=torch.long), dst=peer_rank)
    dist.send(attention_mask.to(dtype=torch.long), dst=peer_rank)
    dist.send(gen_ids_batch.to(dtype=torch.long), dst=peer_rank)
    out = torch.empty((B,), device=input_ids.device, dtype=torch.float32)
    dist.recv(out, src=peer_rank)
    return out

def paired_ref_worker_loop(ref_model: torch.nn.Module, device: torch.device, *, pair_group: Optional[dist.ProcessGroup]) -> None:
    (rank, _, world_size) = dist_info()
    peer = _env_int('PAIRED_REF_PEER', -1)
    if peer < 0:
        raise RuntimeError('PAIRED_REF_PEER env var not set for ref worker rank')
    dbg = bool(os.environ.get('DEBUG_DIST', '0') == '1')
    while True:
        hdr = torch.empty((3,), device=device, dtype=torch.long)
        if pair_group is not None:
            _dprint(dbg, rank, 'ref: waiting hdr (group_src=0)')
            dist.recv(hdr, group=pair_group, group_src=0)
        else:
            _dprint(dbg, rank, f'ref: waiting hdr (src={peer})')
            dist.recv(hdr, src=peer)
        B = int(hdr[0].item())
        L = int(hdr[1].item())
        G = int(hdr[2].item())
        _dprint(dbg, rank, f'ref: got hdr B={B} L={L} G={G}')
        if B == 0 and L == 0 and (G == 0):
            break
        inp = torch.empty((1, L), device=device, dtype=torch.long)
        am = torch.empty((1, L), device=device, dtype=torch.long)
        gen = torch.empty((B, G), device=device, dtype=torch.long)
        if pair_group is not None:
            _dprint(dbg, rank, 'ref: recv payload (group_src=0)')
            dist.recv(inp, group=pair_group, group_src=0)
            dist.recv(am, group=pair_group, group_src=0)
            dist.recv(gen, group=pair_group, group_src=0)
        else:
            _dprint(dbg, rank, f'ref: recv payload (src={peer})')
            dist.recv(inp, src=peer)
            dist.recv(am, src=peer)
            dist.recv(gen, src=peer)
        with torch.no_grad():
            inp_b = inp.expand(B, -1).contiguous()
            am_b = am.expand(B, -1).contiguous()
            lp = compute_sequence_logprob(ref_model, inp_b, gen, am_b)
        lp_out = lp.to(device=device, dtype=torch.float32).view(B)
        if pair_group is not None:
            _dprint(dbg, rank, 'ref: send lp (group_dst=0)')
            dist.send(lp_out, group=pair_group, group_dst=0)
        else:
            _dprint(dbg, rank, f'ref: send lp (dst={peer})')
            dist.send(lp_out, dst=peer)

def main() -> None:
    parser = argparse.ArgumentParser(description='Paired-ref GRPO-style RL for LoRA repair model (compile+slither constraint).')
    parser.add_argument('--train-jsonl', type=str, required=True, help='Training JSONL (fix_sft format)')
    parser.add_argument('--limit', type=int, default=400, help='Max samples for quick run (e.g., 200-500)')
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--base-model', type=str, required=True, help='Base HF model path/name')
    parser.add_argument('--sft-lora', type=str, required=True, help='SFT LoRA checkpoint dir')
    parser.add_argument('--prompt-format', type=str, default='auto', choices=['auto', 'plain', 'chat'])
    parser.add_argument('--dtype', type=str, default='auto', choices=['auto', 'fp16', 'bf16', 'fp32'])
    parser.add_argument('--gradient-checkpointing', action='store_true')
    parser.add_argument('--debug-verify', action='store_true')
    parser.add_argument('--debug-save-contracts', action='store_true')
    parser.add_argument('--mythril', action='store_true')
    parser.add_argument('--mythril-timeout', type=int, default=10)
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
    parser.add_argument('--max-orig-sim', type=float, default=None, help='If set, candidates with text similarity(original_func, new_func) >= threshold will be treated as non-success (and incur extra cost). Example: 0.995')
    parser.add_argument('--orig-sim-cost', type=float, default=1.0, help='Extra constraint cost added when a candidate is too similar to the original (only when --max-orig-sim is set).')
    parser.add_argument('--epsilon-cost', type=float, default=0.5)
    parser.add_argument('--lambda-init', type=float, default=0.0)
    parser.add_argument('--lambda-lr', type=float, default=0.05)
    parser.add_argument('--out-dir', type=str, default='results/rl_lora_quick_pairedref')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--profile', action='store_true', help='Log step-level timing breakdown to out_dir/profile.jsonl')
    parser.add_argument('--profile-sync', action='store_true', help='Add torch.cuda.synchronize() around timed regions for more accurate GPU timings (slower).')
    parser.add_argument('--debug-dist', action='store_true', help='Print rank-local progress markers (send/recv/barrier) with timestamps to debug hangs.')
    parser.add_argument('--no-step-barrier', action='store_true', help='Disable any explicit per-step barrier. Recommended for stability; DDP backward already synchronizes grads.')
    parser.add_argument('--no-final-barrier', action='store_true', help='Disable final global barrier on exit (prevents hangs if some ranks crash/hang).')
    parser.add_argument('--db-path', type=str, default=None)
    parser.add_argument('--use-db-contract', action='store_true')
    parser.add_argument('--ref-mode', type=str, default='local', choices=['local', 'paired'], help='local: ref runs in the same process/device as policy (world_size=1 recommended); paired: dedicate ranks for ref inference (world_size=2/4).')
    parser.add_argument('--ref-on-cpu', action='store_true', help='(local mode only) load ref on CPU (KL becomes slow).')
    parser.add_argument('--rag-mode', type=str, default='off', choices=['off', 'always', 'gate'], help='RAG usage mode: off=disable; always=always use RAG-augmented prompt; gate=train a small RL gate to decide per-sample.')
    parser.add_argument('--rag-index-path', type=str, default=None, help='Path to a saved RAG index dir (HybridRetriever.save/load).')
    parser.add_argument('--rag-build-from-jsonl', type=str, default=None, help='If set (or if rag-index-path missing), build RAG corpus from this fix_sft jsonl (expects input/output fields).')
    parser.add_argument('--rag-build-limit', type=int, default=5000, help='Max docs to build RAG index from jsonl.')
    parser.add_argument('--rag-top-k', type=int, default=3, help='How many retrieval results to use.')
    parser.add_argument('--rag-max-demos', type=int, default=3, help='How many demos to inject into the prompt.')
    parser.add_argument('--rag-mmr-lambda', type=float, default=0.7, help='MMR lambda for demo diversity.')
    parser.add_argument('--rag-fusion-weights', type=str, default='0.35,0.35,0.2,0.1', help='Weights token,bm25,dense,struct.')
    parser.add_argument('--rag-gate-lr', type=float, default=0.0005, help='Learning rate for the RAG gate policy.')
    parser.add_argument('--rag-gate-hidden', type=int, default=64, help='Hidden size for the RAG gate policy MLP.')
    parser.add_argument('--rag-gate-baseline-momentum', type=float, default=0.9, help='EMA baseline momentum for gate REINFORCE.')
    parser.add_argument('--verbose-dump-per-step', type=int, default=0, help='When --verbose is set, dump up to N samples per step: prompt, reference output, and model candidates (rank0 only).')
    parser.add_argument('--verbose-dump-max-chars', type=int, default=2000, help='Max chars to print per dumped field.')
    parser.add_argument('--verbose-dump-cands', type=int, default=2, help='How many candidates to print per dumped sample.')
    args = parser.parse_args()
    if bool(getattr(args, 'verbose', False)):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
        logging.getLogger('smart_contract_vulnerability_detection.src.tools.rag_retriever').setLevel(logging.DEBUG)
    (rank, local_rank, world_size) = init_dist_if_needed()
    device = torch.device(f'cuda:{local_rank}' if torch.cuda.is_available() else 'cpu')
    if args.ref_mode == 'paired':
        if world_size not in (2, 4):
            raise ValueError('--ref-mode paired requires world_size=2 or 4')
        num_policy = world_size // 2
    else:
        num_policy = world_size
    is_policy_rank = rank < num_policy
    peer_ref_rank = rank + num_policy if args.ref_mode == 'paired' and is_policy_rank else None
    _dprint(bool(args.debug_dist), rank, f"init world_size={world_size} local_rank={local_rank} device={device} role={('policy' if is_policy_rank else 'ref')} num_policy={num_policy} peer_ref_rank={peer_ref_rank}")
    if args.ref_mode == 'paired' and (not is_policy_rank):
        os.environ['PAIRED_REF_PEER'] = str(rank - num_policy)
        _dprint(bool(args.debug_dist), rank, f"set PAIRED_REF_PEER={os.environ.get('PAIRED_REF_PEER')}")
    (pg_policy, _pg_ref, pg_pair) = _make_groups(world_size, num_policy, ref_mode=args.ref_mode, rank=rank)
    _dprint(bool(args.debug_dist), rank, f"groups pg_policy={('yes' if pg_policy else 'no')} pg_pair={('yes' if pg_pair else 'no')}")
    seed_rank = rank if is_policy_rank else rank - num_policy
    random.seed(args.seed + seed_rank)
    torch.manual_seed(args.seed + seed_rank)
    out_dir = Path(args.out_dir)
    if rank == 0 and is_policy_rank:
        out_dir.mkdir(parents=True, exist_ok=True)
    if world_size > 1:
        dist.barrier()
    log_path = out_dir / 'train_log.jsonl'
    profile_path = out_dir / 'profile.jsonl'
    debug_save_dir = out_dir / 'debug_contracts' if args.debug_verify and args.debug_save_contracts and (rank == 0) else None
    tok = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
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
        if device.type == 'cuda':
            try:
                if torch.cuda.is_bf16_supported():
                    return torch.bfloat16
            except Exception:
                pass
            return torch.float16
        return torch.float32
    dtype = _resolve_dtype()
    data: List[Dict[str, Any]] = []
    db_session = None
    slice_builder = None
    db_cache: Dict[int, Any] = {}
    if is_policy_rank:
        data = load_jsonl(args.train_jsonl, limit=args.limit, seed=args.seed)
        if not data:
            raise RuntimeError('No data loaded.')
        if args.use_db_contract:
            if not args.db_path or DBManager is None:
                raise ValueError('--use-db-contract requires --db-path and DBManager module')
            db_session = DBManager(args.db_path).get_session()
        slice_builder = CodeSliceBuilder(include_comments=bool(args.verbose)) if CodeSliceBuilder else None
    policy = None
    ref = None
    if is_policy_rank:
        policy_base = AutoModelForCausalLM.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=dtype, device_map=None, low_cpu_mem_usage=True)
        if args.gradient_checkpointing:
            policy_base.gradient_checkpointing_enable()
            try:
                policy_base.enable_input_require_grads()
            except Exception:
                pass
            policy_base.config.use_cache = False
        policy_base.to(device)
        policy = PeftModel.from_pretrained(policy_base, args.sft_lora, is_trainable=True)
        policy.train()
        if args.gradient_checkpointing:
            force_input_embeddings_require_grads(policy)
        if world_size > 1 and pg_policy is not None and (num_policy > 1):
            from torch.nn.parallel import DistributedDataParallel as DDP
            policy = DDP(policy, device_ids=[local_rank], output_device=local_rank, process_group=pg_policy)
    else:
        ref_base = AutoModelForCausalLM.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=dtype, device_map=None, low_cpu_mem_usage=True)
        ref_base.to(device)
        ref = PeftModel.from_pretrained(ref_base, args.sft_lora).to(device)
        ref.eval()
        for p in ref.parameters():
            p.requires_grad_(False)
        if bool(args.debug_dist):
            os.environ['DEBUG_DIST'] = '1'
        paired_ref_worker_loop(ref, device, pair_group=pg_pair)
        if world_size > 1:
            dist.barrier()
        return
    assert policy is not None
    use_rag = str(args.rag_mode).lower() in {'always', 'gate'}
    retriever = None
    rag_builder = None
    if use_rag:
        if HybridRetriever is None or RAGPromptBuilder is None:
            raise RuntimeError('RAG requested but src.tools.rag_retriever is unavailable.')
        w = tuple((float(x.strip()) for x in str(args.rag_fusion_weights).split(',') if x.strip()))
        if len(w) != 4:
            raise ValueError('--rag-fusion-weights must have 4 comma-separated floats: token,bm25,dense,struct')
        retriever = HybridRetriever(fusion_weights=w, mmr_lambda=float(args.rag_mmr_lambda))
        rag_builder = RAGPromptBuilder(max_demos=int(args.rag_max_demos))
        idx_path = args.rag_index_path
        built = False
        if idx_path and Path(idx_path).exists():
            retriever.load(str(idx_path))
        else:
            build_src = args.rag_build_from_jsonl or (args.train_jsonl if hasattr(args, 'train_jsonl') else None)
            if not build_src:
                raise ValueError('RAG enabled but no index found and --rag-build-from-jsonl not provided.')
            if build_documents_from_fix_sft_jsonl is None:
                raise RuntimeError('build_documents_from_fix_sft_jsonl unavailable (rag_retriever import failed).')
            docs = build_documents_from_fix_sft_jsonl(str(build_src), limit=int(args.rag_build_limit))
            if not docs:
                raise RuntimeError(f'RAG build produced 0 docs from: {build_src}')
            retriever.build(docs)
            built = True
            if idx_path:
                Path(idx_path).mkdir(parents=True, exist_ok=True)
                retriever.save(str(idx_path))
        if rank == 0:
            mode = str(args.rag_mode)
            print(f"[rag] enabled mode={mode} index={('loaded' if idx_path and Path(idx_path).exists() and (not built) else 'built')} docs={len(getattr(retriever, '_docs', []) or [])}")
    gate_policy = None
    gate_opt = None
    gate_baseline = 0.0
    if str(args.rag_mode).lower() == 'gate':
        gate_policy = RagGatePolicy(obs_dim=10, hidden=int(args.rag_gate_hidden)).to(device)
        gate_opt = AdamW(gate_policy.parameters(), lr=float(args.rag_gate_lr))
        gate_baseline = 0.0
    ref_local = None
    ref_local_device: str = str(device)
    if args.ref_mode == 'local':
        if world_size != 1:
            raise RuntimeError('--ref-mode local is only supported with world_size=1 in this pairedref script')
        ref_local_device = 'cpu' if args.ref_on_cpu else str(device)
        ref_base = AutoModelForCausalLM.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=torch.float32 if ref_local_device == 'cpu' else dtype, device_map=None, low_cpu_mem_usage=True)
        ref_base.to(ref_local_device)
        ref_local = PeftModel.from_pretrained(ref_base, args.sft_lora).to(ref_local_device)
        ref_local.eval()
        for p in ref_local.parameters():
            p.requires_grad_(False)
    trainable_params = [p for p in policy.parameters() if p.requires_grad]
    if not trainable_params:
        raise RuntimeError('No trainable parameters found in LoRA.')
    opt = AdamW(trainable_params, lr=args.lr)
    slither_mgr = SlitherManager(debug=args.verbose) if SlitherManager and is_policy_rank else None
    mythril_mgr = MythrilManager(debug=args.verbose) if args.mythril and MythrilManager and is_policy_rank else None
    mythril_severities = tuple([s.strip().lower() for s in str(args.mythril_severities).split(',') if s.strip()])
    encoder = None
    if SentenceTransformer and is_policy_rank:
        try:
            encoder = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
        except Exception:
            encoder = None
    verify_cache: Dict[str, VerifyResult] = {}
    lagrange_lambda = float(args.lambda_init)
    policy_rank = rank
    idx = policy_rank
    log_f = open(log_path, 'a', encoding='utf-8') if rank == 0 else None
    prof_f = open(profile_path, 'a', encoding='utf-8') if rank == 0 and bool(args.profile) else None
    try:
        for step in range(1, args.steps + 1):
            if rank == 0:
                print(f'[step {step}] start (world_size={world_size} policy_ranks={num_policy} ref_mode={args.ref_mode})', flush=True)
            _dprint(bool(args.debug_dist), rank, f'step {step}: begin')
            step_t = {'tokenize_s': 0.0, 'gen_s': 0.0, 'verify_s': 0.0, 'ref_lp_s': 0.0, 'pol_lp_s': 0.0, 'backward_s': 0.0, 'opt_s': 0.0}
            step_counts = {'cands': 0, 'verified': 0, 'compile_calls': 0, 'slither_calls': 0, 'mythril_calls': 0}
            batch_items = []
            for _ in range(args.batch_prompts):
                batch_items.append(data[idx % len(data)])
                idx += num_policy
            total_loss = 0.0
            batch_costs: List[float] = []
            batch_rewards: List[float] = []
            batch_success: List[int] = []
            opt.zero_grad(set_to_none=True)
            dump_left = int(getattr(args, 'verbose_dump_per_step', 0)) if rank == 0 and bool(args.verbose) else 0
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
                use_rag_now = False
                gate_logprob = None
                if use_rag and retriever is not None and (rag_builder is not None):
                    if str(args.rag_mode).lower() == 'always':
                        use_rag_now = True
                    elif str(args.rag_mode).lower() == 'gate' and gate_policy is not None:
                        obs = _gate_features(inp).to(device).unsqueeze(0)
                        logits = gate_policy(obs)
                        dist_cat = torch.distributions.Categorical(logits=logits)
                        act = dist_cat.sample()
                        gate_logprob = dist_cat.log_prob(act).squeeze(0)
                        use_rag_now = bool(int(act.item()) == 1)
                inp_for_prompt = inp
                if use_rag_now and retriever is not None and (rag_builder is not None):
                    q = orig_func or contract or inp
                    vuln_info = parse_vuln_info_from_text(inp) if parse_vuln_info_from_text is not None else {'vulnerability_types': ['Unknown'], 'severity': 'Unknown'}
                    vt = None
                    try:
                        vts = vuln_info.get('vulnerability_types') or []
                        if isinstance(vts, list) and vts:
                            vt = str(vts[0])
                    except Exception:
                        vt = None
                    demos = retriever.search(q, top_k=int(args.rag_top_k), vuln_type=vt, use_mmr=True)
                    inp_for_prompt = rag_builder.build(query_code=q, vuln_info=vuln_info, examples=demos)
                    if bool(args.verbose) and rank == 0:
                        print(f'[rag] sample={sample_id} fn={func_name} use_rag=1 demos={len(demos)} vt={vt}')
                elif bool(args.verbose) and rank == 0 and use_rag:
                    print(f'[rag] sample={sample_id} fn={func_name} use_rag=0')
                prompt = build_prompt(tok, instruction, inp_for_prompt, function_name=func_name, prompt_format=args.prompt_format)
                if dump_left > 0:
                    dump_left -= 1
                    ref_out = str(item.get('output', '') or '')
                    ref_func = _extract_function_block_from_text(ref_out, func_name) or strip_code_fences(ref_out)
                    print('\n' + '=' * 100)
                    print(f'[dump][step={step}] sample_id={sample_id} function={func_name} rag_mode={args.rag_mode} use_rag={(1 if use_rag_now else 0)}')
                    print('-' * 100)
                    print('[dump] PROMPT:\n' + _clip(prompt, int(getattr(args, 'verbose_dump_max_chars', 2000))))
                    print('-' * 100)
                    if ref_func.strip():
                        print('[dump] REFERENCE (jsonl.output, extracted):\n' + _clip(ref_func, int(getattr(args, 'verbose_dump_max_chars', 2000))))
                    else:
                        print('[dump] REFERENCE: <missing output field in jsonl>')
                    print('=' * 100)
                tt = _Timer()
                tt.start()
                enc = tok(prompt, return_tensors='pt', truncation=True, max_length=args.max_prompt_len)
                input_ids = enc['input_ids'].to(device)
                attn = enc['attention_mask'].to(device)
                step_t['tokenize_s'] += tt.stop()
                cand_texts: List[str] = []
                cand_ids: List[torch.Tensor] = []
                was_training = policy.training
                policy.eval()
                _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                tt = _Timer()
                tt.start()
                with torch.no_grad():
                    gen_model = policy.module if hasattr(policy, 'module') else policy
                    remaining = int(args.k)
                    gen_mb = max(1, int(getattr(args, 'gen_microbatch', 1)))
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
                _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                step_t['gen_s'] += tt.stop()
                if was_training:
                    policy.train()
                _dprint(bool(args.debug_dist), rank, f'step {step}: generated {len(cand_ids)} candidates')
                if bool(args.verbose) and rank == 0 and (int(getattr(args, 'verbose_dump_per_step', 0)) > 0):
                    show_n = min(int(getattr(args, 'verbose_dump_cands', 2)), len(cand_texts))
                    for i in range(show_n):
                        print('-' * 100)
                        print(f'[dump] CANDIDATE[{i}]:\n' + _clip(str(cand_texts[i] or ''), int(getattr(args, 'verbose_dump_max_chars', 2000))))
                ref_lps: List[torch.Tensor] = []
                mb = max(1, int(getattr(args, 'gen_microbatch', 1)))
                if args.ref_mode == 'paired':
                    assert peer_ref_rank is not None
                    _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                    tt = _Timer()
                    tt.start()
                    for s in range(0, len(cand_ids), mb):
                        e = min(len(cand_ids), s + mb)
                        gen_b = torch.cat([t.to(device) for t in cand_ids[s:e]], dim=0)
                        _dprint(bool(args.debug_dist), rank, f'step {step}: ref_batch s={s} e={e} -> peer_rank={int(peer_ref_rank)}')
                        lp_b = paired_ref_request_batch(peer_rank=int(peer_ref_rank), input_ids=input_ids, attention_mask=attn, gen_ids_batch=gen_b, pair_group=pg_pair)
                        for i in range(lp_b.shape[0]):
                            ref_lps.append(lp_b[i:i + 1].to(device))
                    _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                    step_t['ref_lp_s'] += tt.stop()
                else:
                    assert ref_local is not None
                    _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                    tt = _Timer()
                    tt.start()
                    for s in range(0, len(cand_ids), mb):
                        e = min(len(cand_ids), s + mb)
                        gen_b = torch.cat([t.to(device) for t in cand_ids[s:e]], dim=0)
                        B = int(gen_b.shape[0])
                        lp_b = compute_sequence_logprob(ref_local, input_ids.to(ref_local_device).expand(B, -1).contiguous(), gen_b.to(ref_local_device), attn.to(ref_local_device).expand(B, -1).contiguous()).to(device=device)
                        for i in range(lp_b.shape[0]):
                            ref_lps.append(lp_b[i:i + 1].to(device))
                    _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                    step_t['ref_lp_s'] += tt.stop()
                if len(ref_lps) != len(cand_ids):
                    raise RuntimeError(f'ref_lps mismatch: got {len(ref_lps)} expected {len(cand_ids)}')
                scores: List[float] = []
                logps: List[torch.Tensor] = []
                total_rs: List[float] = []
                for (cand_i, (gen_ids, gen_txt)) in enumerate(zip(cand_ids, cand_texts)):
                    cand_tag = f'{sample_id}_{func_name}_k{cand_i}'
                    step_counts['cands'] += 1
                    fixed_func = _extract_function_block_from_text(gen_txt, func_name)
                    if not fixed_func:
                        fixed_func = _wrap_body_into_original_function(orig_func, gen_txt)
                    new_func_for_reward = fixed_func or ''
                    orig_sim = 0.0
                    too_similar = False
                    try:
                        if orig_func and new_func_for_reward:
                            if text_similarity is not None:
                                orig_sim = float(text_similarity(orig_func, new_func_for_reward))
                            else:
                                import difflib
                                orig_sim = float(difflib.SequenceMatcher(a=orig_func, b=new_func_for_reward).ratio())
                        thr = getattr(args, 'max_orig_sim', None)
                        if thr is not None:
                            too_similar = bool(orig_sim >= float(thr))
                    except Exception:
                        orig_sim = 0.0
                        too_similar = False
                    vt = _Timer()
                    vt.start()
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
                                step_counts['compile_calls'] += 1
                                (ok, cerr, _) = compile_contract(slither_mgr, repaired, debug=args.debug_verify, debug_save_dir=debug_save_dir, tag=cand_tag) if slither_mgr else (False, 'no_mgr', None)
                                if not ok:
                                    vr = VerifyResult(False, False, 0, [], cerr, True, 0, [], None)
                                else:
                                    step_counts['slither_calls'] += 1
                                    (sp, ic, issues, serr) = slither_check(slither_mgr, repaired, debug=args.debug_verify, debug_save_dir=debug_save_dir, tag=cand_tag)
                                    (mp, mic, missues, merr) = (True, 0, [], None)
                                    if mythril_mgr:
                                        step_counts['mythril_calls'] += 1
                                        (mp, mic, missues, merr) = mythril_check(mythril_mgr, repaired, timeout=args.mythril_timeout, severities=mythril_severities, debug=args.debug_verify, debug_save_dir=debug_save_dir, tag=cand_tag)
                                    vr = VerifyResult(True, sp, ic, issues, serr, mp, mic, missues, merr)
                                verify_cache[vkey] = vr
                                step_counts['verified'] += 1
                    step_t['verify_s'] += vt.stop()
                    if not vr.compiles:
                        cost = 5.0
                    elif not vr.slither_passed or (args.mythril and (not vr.mythril_passed)):
                        cost = float(max(1, vr.issue_count))
                    else:
                        cost = 0.0
                    if too_similar:
                        cost = float(cost + float(getattr(args, 'orig_sim_cost', 1.0)))
                    r_stmt = args.w_stmt * (1.0 if vr.compiles else 0.0)
                    r_func = function_reward(encoder, orig_func, new_func_for_reward, args.w_func_embed, args.w_func_edit)
                    ok_security = vr.slither_passed and (vr.mythril_passed if args.mythril else True)
                    if vr.compiles and ok_security:
                        if too_similar:
                            r_ver = args.compile_only_bonus
                            success = 0
                        else:
                            r_ver = args.success_bonus
                            success = 1
                    elif vr.compiles:
                        r_ver = args.compile_only_bonus
                        success = 0
                    else:
                        r_ver = 0.0
                        success = 0
                    ref_lp = ref_lps[cand_i]
                    gen_ids_on_policy = gen_ids.to(device)
                    _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                    tt = _Timer()
                    tt.start()
                    policy_out = policy(input_ids=torch.cat([input_ids, gen_ids_on_policy], dim=1), attention_mask=torch.cat([attn, torch.ones_like(gen_ids_on_policy)], dim=1), use_cache=False)
                    L = input_ids.shape[1]
                    G = gen_ids_on_policy.shape[1]
                    pred_logits = policy_out.logits[:, L - 1:L + G - 1, :].contiguous()
                    pol_lp = _gather_logprobs(pred_logits, gen_ids_on_policy).sum(dim=1)
                    del policy_out, pred_logits
                    _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                    step_t['pol_lp_s'] += tt.stop()
                    kl_approx = (pol_lp - ref_lp.to(pol_lp.device)) / max(1.0, float(G))
                    r_tok = -args.kl_beta * float(kl_approx.item())
                    total_r = float(r_stmt + r_func + r_ver + r_tok)
                    score = total_r - lagrange_lambda * cost
                    scores.append(score)
                    logps.append(pol_lp.squeeze(0))
                    batch_costs.append(cost)
                    batch_rewards.append(total_r)
                    batch_success.append(success)
                    total_rs.append(total_r)
                if not scores:
                    continue
                baseline = sum(scores) / len(scores)
                adv = torch.tensor([s - baseline for s in scores], dtype=torch.float32, device=device)
                logp_stack = torch.stack(logps, dim=0).to(device)
                loss = -(adv.detach() * logp_stack).mean()
                loss = loss / max(1, args.grad_accum)
                _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                tt = _Timer()
                tt.start()
                loss.backward()
                _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
                step_t['backward_s'] += tt.stop()
                total_loss += float(loss.item())
                if gate_policy is not None and gate_opt is not None and (gate_logprob is not None):
                    best_score = float(max(scores)) if scores else 0.0
                    m = float(args.rag_gate_baseline_momentum)
                    gate_baseline = m * gate_baseline + (1.0 - m) * best_score
                    gate_adv = float(best_score - gate_baseline)
                    gate_loss = -(gate_adv * gate_logprob)
                    gate_opt.zero_grad(set_to_none=True)
                    gate_loss.backward()
                    gate_opt.step()
            _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
            tt = _Timer()
            tt.start()
            torch.nn.utils.clip_grad_norm_([p for p in policy.parameters() if p.requires_grad], max_norm=1.0)
            opt.step()
            _maybe_cuda_sync(device, bool(args.profile and args.profile_sync))
            step_t['opt_s'] += tt.stop()
            local_reward_sum = float(sum(batch_rewards)) if batch_rewards else 0.0
            local_succ_sum = float(sum(batch_success)) if batch_success else 0.0
            local_cost_sum = float(sum(batch_costs)) if batch_costs else 0.0
            local_count = float(len(batch_success)) if batch_success else 0.0
            if world_size > 1 and pg_policy is not None and (num_policy >= 1):
                t = torch.tensor([local_reward_sum, local_succ_sum, local_cost_sum, local_count], device=device, dtype=torch.float32)
                dist.all_reduce(t, op=dist.ReduceOp.SUM, group=pg_policy)
                (g_reward_sum, g_succ_sum, g_cost_sum, g_count) = [float(x) for x in t.tolist()]
                g_count = max(1.0, g_count)
                avg_reward = g_reward_sum / g_count
                succ_rate = g_succ_sum / g_count
                g_cost = g_cost_sum / g_count
            else:
                denom = max(1.0, local_count)
                avg_reward = local_reward_sum / denom
                succ_rate = local_succ_sum / denom
                g_cost = local_cost_sum / denom
            lagrange_lambda = max(0.0, lagrange_lambda + args.lambda_lr * (g_cost - args.epsilon_cost))
            if rank == 0:
                print(f'[step {step}] reward={avg_reward:.3f} cost={g_cost:.3f} succ={succ_rate:.2%} lambda={lagrange_lambda:.3f}')
                if log_f:
                    log_f.write(json.dumps({'step': step, 'reward': avg_reward, 'cost': g_cost, 'lambda': lagrange_lambda, 'loss': total_loss}) + '\n')
                    log_f.flush()
            if bool(args.profile) and rank < num_policy:
                if world_size > 1 and pg_policy is not None and (num_policy >= 1):
                    t = torch.tensor([step_t['tokenize_s'], step_t['gen_s'], step_t['verify_s'], step_t['ref_lp_s'], step_t['pol_lp_s'], step_t['backward_s'], step_t['opt_s'], float(step_counts['cands']), float(step_counts['verified']), float(step_counts['compile_calls']), float(step_counts['slither_calls']), float(step_counts['mythril_calls'])], device=device, dtype=torch.float32)
                    dist.all_reduce(t, op=dist.ReduceOp.SUM, group=pg_policy)
                    denom = float(max(1, num_policy))
                    t = t / denom
                    (tokenize_s, gen_s, verify_s, ref_lp_s, pol_lp_s, backward_s, opt_s, cands, verified, compile_calls, slither_calls, mythril_calls) = [float(x) for x in t.tolist()]
                else:
                    tokenize_s = float(step_t['tokenize_s'])
                    gen_s = float(step_t['gen_s'])
                    verify_s = float(step_t['verify_s'])
                    ref_lp_s = float(step_t['ref_lp_s'])
                    pol_lp_s = float(step_t['pol_lp_s'])
                    backward_s = float(step_t['backward_s'])
                    opt_s = float(step_t['opt_s'])
                    cands = float(step_counts['cands'])
                    verified = float(step_counts['verified'])
                    compile_calls = float(step_counts['compile_calls'])
                    slither_calls = float(step_counts['slither_calls'])
                    mythril_calls = float(step_counts['mythril_calls'])
                if prof_f:
                    prof_f.write(json.dumps({'step': step, 'world_size': world_size, 'policy_ranks': num_policy, 'ref_mode': args.ref_mode, 'k': int(args.k), 'gen_microbatch': int(getattr(args, 'gen_microbatch', 1)), 'batch_prompts': int(args.batch_prompts), 'timing_s': {'tokenize': tokenize_s, 'generate': gen_s, 'verify': verify_s, 'ref_logprob': ref_lp_s, 'policy_logprob': pol_lp_s, 'backward': backward_s, 'opt': opt_s}, 'counts': {'cands': cands, 'verified': verified, 'compile_calls': compile_calls, 'slither_calls': slither_calls, 'mythril_calls': mythril_calls}}) + '\n')
                    prof_f.flush()
            if not bool(args.no_step_barrier) and world_size > 1 and (pg_policy is not None) and (num_policy > 1):
                _dprint(bool(args.debug_dist), rank, f'step {step}: enter policy barrier')
                dist.barrier(group=pg_policy)
                _dprint(bool(args.debug_dist), rank, f'step {step}: exit policy barrier')
        if rank == 0:
            save_dir = out_dir / 'rl_lora'
            save_dir.mkdir(parents=True, exist_ok=True)
            m = policy.module if hasattr(policy, 'module') else policy
            m.save_pretrained(str(save_dir))
            tok.save_pretrained(str(save_dir))
            print(f'Saved to {save_dir}')
    finally:
        if args.ref_mode == 'paired' and peer_ref_rank is not None and (world_size > 1):
            stop = torch.tensor([0, 0, 0], device=device, dtype=torch.long)
            if pg_pair is not None:
                dist.send(stop, group=pg_pair, group_dst=1)
            else:
                dist.send(stop, dst=int(peer_ref_rank))
        if log_f:
            log_f.close()
        if prof_f:
            prof_f.close()
        if db_session:
            try:
                db_session.close()
            except Exception:
                pass
        if ref_local is not None:
            try:
                del ref_local
            except Exception:
                pass
        if not bool(args.no_final_barrier) and world_size > 1:
            dist.barrier()
if __name__ == '__main__':
    main()
