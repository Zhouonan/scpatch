import json
import time
import os
import tempfile
import subprocess
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from openai import OpenAI
from src.tools.slice_builder import CodeSliceBuilder
from src.tools.slither_manager import SlitherManager
from src.tools.mythril_manager import MythrilManager
from src.tools.slither_utils import collect_slither_issues

@dataclass
class FixerConfig:
    api_key: str
    base_url: str = 'https://api.deepseek.com'
    model: str = 'deepseek-reasoner'
    temperature: float = 0.2
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None
    seed: Optional[int] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    retry_temperature: float = 0.1
    timeout: int = 90
    max_retries: int = 3
    retry_delay: int = 5
    verbose: bool = False
    print_llm_responses: bool = False
    llm_responses_out: Optional[str] = None
    llm_responses_append_pid: bool = False
    reasoning_effort: Optional[str] = None
    max_output_tokens: Optional[int] = None
    enable_compilation_check: bool = False
    enable_slither_check: bool = False
    solc_version: str = '0.8.0'
    max_fix_attempts: int = 1
    enable_mythril_check: bool = False
    mythril_timeout: int = 120
    mythril_severities: Optional[List[str]] = None
    mythril_bin: str = 'myth'
    strict_verification: bool = False
    mythril_uncertain_as_pass: bool = True
    evaluation_mode: bool = False
    stop: Optional[List[str]] = None
    force_single_n_model_keywords: List[str] = field(default_factory=lambda : ['deepseek', 'qwen3-vl-32b-instruct'])
    force_single_n: bool = False
    llm_request_workers: int = 1
    allow_n_fallback: bool = True
    use_rich_fix_prompt: bool = False
    enable_error_feedback: bool = True
    max_error_lines: int = 10
    rag_mode: str = 'off'
    rag_index_path: Optional[str] = None
    rag_build_from_jsonl: Optional[str] = None
    rag_build_limit: int = 5000
    rag_top_k: int = 3
    rag_max_demos: int = 3
    rag_max_chars_each: int = 800
    rag_max_added_tokens: Optional[int] = None
    rag_mmr_lambda: float = 0.7
    rag_fusion_weights: str = '0.35,0.35,0.2,0.1'

def _append_jsonl(path: str, obj: Dict) -> None:
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(obj, ensure_ascii=False) + '\n')
    except Exception:
        return

def _maybe_add_reasoning_controls(extra_body: Dict, cfg: FixerConfig) -> Dict:
    try:
        eb = dict(extra_body) if isinstance(extra_body, dict) else {}
        eff = getattr(cfg, 'reasoning_effort', None)
        if eff is not None:
            s = str(eff).strip()
            if s:
                eb['reasoning_effort'] = s
        mot = getattr(cfg, 'max_output_tokens', None)
        if mot is not None:
            try:
                eb['max_output_tokens'] = int(mot)
            except Exception:
                pass
        return eb
    except Exception:
        return extra_body if isinstance(extra_body, dict) else {}

def _strip_reasoning_controls_on_error(extra_body: Dict, err: Exception) -> Tuple[Dict, bool]:
    try:
        if not isinstance(extra_body, dict) or not extra_body:
            return (extra_body, False)
        msg = str(err).lower()
        keys = ['reasoning_effort', 'max_output_tokens']
        if not any((k in msg for k in ['unknown', 'unrecognized', 'invalid', 'extra fields', 'additional properties'])):
            return (extra_body, False)
        if not any((k in msg for k in ['reasoning', 'max_output_tokens', 'output_tokens'])):
            return (extra_body, False)
        eb = dict(extra_body)
        did = False
        for k in keys:
            if k in eb:
                eb.pop(k, None)
                did = True
        return (eb, did)
    except Exception:
        return (extra_body, False)

class LLMFixer:

    def __init__(self, config: FixerConfig):
        self.config = config
        self.client = OpenAI(api_key=config.api_key, base_url=config.base_url, timeout=config.timeout)
        self.slice_builder = CodeSliceBuilder(include_comments=False)
        self.slither_manager = SlitherManager(debug=config.verbose)
        self.mythril_manager = MythrilManager(debug=config.verbose, mythril_bin=config.mythril_bin)
        from src.tools.prompt_formatter import PromptFormatter
        self.prompt_formatter = PromptFormatter()
        self._reference_ir_cache: Dict[str, List[str]] = {}
        self._rag_enabled: bool = False
        self._rag_retriever = None
        self._rag_builder = None
        self._rag_parse_vuln_info = None
        self._rag_extract_function_block = None
        self._rag_init_error: Optional[str] = None
        try:
            self._init_rag_if_needed()
        except Exception as e:
            self._rag_enabled = False
            self._rag_retriever = None
            self._rag_builder = None
            self._rag_parse_vuln_info = None
            self._rag_init_error = f'{type(e).__name__}: {e}'
        self.stats = {'total_requests': 0, 'successful_fixes': 0, 'failed_fixes': 0, 'compilation_failures': 0, 'slither_check_failures': 0, 'prompt_tokens_used': 0, 'completion_tokens_used': 0, 'total_tokens_used': 0, 'api_errors': 0, 'fix_attempts_distribution': {}, 'retry_successes': 0, 'error_feedback_used': 0, 'compilation_retry_successes': 0}

    def _init_rag_if_needed(self) -> None:
        mode = str(getattr(self.config, 'rag_mode', 'off') or 'off').strip().lower()
        if mode not in {'always'}:
            self._rag_enabled = False
            return
        from src.tools.rag_retriever import HybridRetriever, RAGPromptBuilder, build_documents_from_fix_sft_jsonl, parse_vuln_info_from_text, extract_function_block
        w_raw = str(getattr(self.config, 'rag_fusion_weights', '0.35,0.35,0.2,0.1') or '0.35,0.35,0.2,0.1')
        w = tuple((float(x.strip()) for x in w_raw.split(',') if x.strip()))
        if len(w) != 4:
            raise ValueError('rag_fusion_weights must have 4 comma-separated floats: token,bm25,dense,struct')
        retriever = HybridRetriever(fusion_weights=w, mmr_lambda=float(getattr(self.config, 'rag_mmr_lambda', 0.7)))
        builder = RAGPromptBuilder(max_demos=int(getattr(self.config, 'rag_max_demos', 3)), max_chars_each=int(getattr(self.config, 'rag_max_chars_each', 800)))
        idx_path = getattr(self.config, 'rag_index_path', None)
        built = False
        if idx_path and os.path.exists(str(idx_path)):
            retriever.load(str(idx_path))
        else:
            build_src = getattr(self.config, 'rag_build_from_jsonl', None)
            if not build_src:
                raise ValueError('RAG enabled but no index found and rag_build_from_jsonl not provided.')
            docs = build_documents_from_fix_sft_jsonl(str(build_src), limit=int(getattr(self.config, 'rag_build_limit', 5000)))
            if not docs:
                raise RuntimeError(f'RAG build produced 0 docs from: {build_src}')
            retriever.build(docs)
            built = True
            if idx_path:
                os.makedirs(str(idx_path), exist_ok=True)
                retriever.save(str(idx_path))
        self._rag_enabled = True
        self._rag_retriever = retriever
        self._rag_builder = builder
        self._rag_parse_vuln_info = parse_vuln_info_from_text
        self._rag_extract_function_block = extract_function_block
        self._rag_init_error = None
        if bool(getattr(self.config, 'verbose', False)):
            src = 'loaded' if idx_path and os.path.exists(str(idx_path)) and (not built) else 'built'
            print(f"[rag] enabled mode={mode} index={src} docs={len(getattr(retriever, '_docs', []) or [])}")

    @staticmethod
    def _format_rag_demo_prefix(demos: List[Any]) -> str:
        if not demos:
            return ''
        parts: List[str] = ['<RAG_DEMOS>']
        for ex in demos:
            try:
                vt = getattr(ex, 'vulnerability_type', '') or 'Unknown'
                code = getattr(ex, 'code', '') or ''
                fixed = getattr(ex, 'fixed_code', '') or ''
            except Exception:
                continue
            parts.append('\n'.join(['<DEMO>', f'### Vulnerable ({vt}):', '```solidity', code, '```', '### Fixed:', '```solidity', fixed, '```', '</DEMO>']))
        parts.append('</RAG_DEMOS>')
        return '\n\n'.join(parts).strip()

    @staticmethod
    def _estimate_tokens(text: str, *, model: Optional[str]=None) -> int:
        t = text or ''
        if not t:
            return 0
        try:
            import tiktoken
            enc = None
            if model:
                try:
                    enc = tiktoken.encoding_for_model(str(model))
                except Exception:
                    enc = None
            if enc is None:
                enc = tiktoken.get_encoding('cl100k_base')
            return int(len(enc.encode(t)))
        except Exception:
            return int(max(1, len(t) // 4))

    @staticmethod
    def _strip_solidity_comments(code: str) -> str:
        import re
        s = code or ''
        if not s:
            return ''
        s = re.sub('/\\*[\\s\\S]*?\\*/', '', s)
        s = re.sub('//.*?$', '', s, flags=re.MULTILINE)
        return s

    @staticmethod
    def _compact_code_block(code: str) -> str:
        s = (code or '').strip()
        if not s:
            return ''
        if '```' in s:
            lines = []
            for ln in s.splitlines():
                if ln.strip().startswith('```'):
                    continue
                lines.append(ln)
            s = '\n'.join(lines).strip()
        s = LLMFixer._strip_solidity_comments(s)
        out_lines: List[str] = []
        blank = False
        for ln in s.splitlines():
            ln = ln.rstrip()
            if not ln.strip():
                if not blank:
                    out_lines.append('')
                blank = True
            else:
                blank = False
                out_lines.append(ln)
        return '\n'.join(out_lines).strip()

    def _compact_demo(self, code: str, *, function_name: Optional[str]=None) -> str:
        raw = code or ''
        if not raw.strip():
            return ''
        fn = (function_name or '').strip() or None
        try:
            if self._rag_extract_function_block is not None:
                extracted = self._rag_extract_function_block(raw, function_name=fn)
                if isinstance(extracted, str) and extracted.strip():
                    return self._compact_code_block(extracted)
        except Exception:
            pass
        return self._compact_code_block(raw)

    def _select_demos_with_token_budget(self, demos: List[Any], *, max_added_tokens: Optional[int]) -> Tuple[List[Any], int]:
        if not demos:
            return ([], 0)
        if max_added_tokens is None:
            prefix = self._format_rag_demo_prefix(demos)
            return (demos, self._estimate_tokens(prefix, model=getattr(self.config, 'model', None)))
        budget = max(0, int(max_added_tokens))
        if budget <= 0:
            return ([], 0)
        selected: List[Any] = []
        base = '<RAG_DEMOS>\n</RAG_DEMOS>'
        cur_tokens = self._estimate_tokens(base, model=getattr(self.config, 'model', None))
        for ex in demos:
            one = self._format_rag_demo_prefix([ex])
            one_tokens = self._estimate_tokens(one, model=getattr(self.config, 'model', None))
            if cur_tokens + one_tokens > budget:
                continue
            selected.append(ex)
            cur_tokens += one_tokens
            if cur_tokens >= budget:
                break
        prefix = self._format_rag_demo_prefix(selected)
        return (selected, self._estimate_tokens(prefix, model=getattr(self.config, 'model', None)))

    def _maybe_apply_rag_to_prompt(self, *, func_data: Dict[str, Any], annotation: Dict[str, Any], prompt: str) -> Tuple[str, Dict[str, Any]]:
        if not self._rag_enabled or self._rag_retriever is None or self._rag_builder is None:
            return (prompt, {'rag_used': False, 'rag_error': self._rag_init_error})
        q_code = str(func_data.get('function_code') or '').strip()
        if not q_code:
            q_code = str(prompt or '').strip()
        vuln_info: Dict[str, Any] = {'vulnerability_types': ['Unknown'], 'severity': 'Unknown'}
        try:
            vts = annotation.get('vulnerability_types') if isinstance(annotation, dict) else None
            if isinstance(vts, list) and vts:
                vuln_info['vulnerability_types'] = vts
            sev = annotation.get('severity') if isinstance(annotation, dict) else None
            if sev is not None:
                vuln_info['severity'] = sev
        except Exception:
            pass
        vt = None
        try:
            if isinstance(vuln_info.get('vulnerability_types'), list) and vuln_info['vulnerability_types']:
                vt = str(vuln_info['vulnerability_types'][0])
        except Exception:
            vt = None
        print(f'  [RAG] Query code length={len(q_code)}, preview={q_code[:150]}...')
        print(f"  [RAG] Vuln type filter={vt}, top_k={int(getattr(self.config, 'rag_top_k', 3))}")
        print(f"  [RAG] Index has {len(getattr(self._rag_retriever, '_docs', []) or [])} docs")
        demos = []
        try:
            demos_no_filter = self._rag_retriever.search(q_code, top_k=int(getattr(self.config, 'rag_top_k', 3)), vuln_type=None, use_mmr=True)
            print(f'  [RAG] Without vuln_type filter: found {len(demos_no_filter)} demos')
            demos = self._rag_retriever.search(q_code, top_k=int(getattr(self.config, 'rag_top_k', 3)), vuln_type=vt, use_mmr=True)
            print(f"  [RAG] With vuln_type filter '{vt}': found {len(demos)} demos")
            if len(demos) == 0 and len(demos_no_filter) > 0:
                print(f"  [RAG] Warning: vuln_type filter '{vt}' too strict, using unfiltered results")
                demos = demos_no_filter[:int(getattr(self.config, 'rag_top_k', 3))]
        except Exception as e:
            print(f'  [RAG] Exception during search: {type(e).__name__}: {e}')
            import traceback
            traceback.print_exc()
            return (prompt, {'rag_used': False, 'rag_error': f'retrieve_failed: {type(e).__name__}: {e}'})
        fn = str(func_data.get('function_name') or '').strip() or 'unknown'
        print(f"\n[RAG] Retrieved {len(demos)} demos for function={fn}, vuln_type={vt or 'any'}")
        for (i, ex) in enumerate(demos):
            score = getattr(ex, 'score', 0.0)
            ex_vt = getattr(ex, 'vulnerability_type', 'Unknown')
            ex_code_preview = (getattr(ex, 'code', '') or '')[:100].replace('\n', ' ')
            print(f'  [RAG] Demo[{i}]: score={score:.3f}, type={ex_vt}, code_preview={ex_code_preview}...')
        compacted: List[Any] = []
        for ex in demos:
            try:
                if hasattr(ex, 'code') and isinstance(ex.code, str):
                    ex.code = self._compact_demo(ex.code, function_name=fn)
                if hasattr(ex, 'fixed_code') and isinstance(ex.fixed_code, str):
                    ex.fixed_code = self._compact_demo(ex.fixed_code, function_name=fn)
            except Exception:
                pass
            compacted.append(ex)
        max_added = getattr(self.config, 'rag_max_added_tokens', None)
        (selected, added_tokens) = self._select_demos_with_token_budget(compacted, max_added_tokens=max_added)
        if len(selected) < len(compacted):
            print(f'  [RAG] Token budget: selected {len(selected)}/{len(compacted)} demos (budget={max_added}, used={added_tokens})')
        else:
            print(f'  [RAG] Using all {len(selected)} demos (estimated tokens={added_tokens})')
        prefix = self._format_rag_demo_prefix(selected)
        new_prompt = (prefix + '\n\n' + (prompt or '')).strip() if prefix else prompt or ''
        demo_summaries: List[Dict[str, Any]] = []
        for ex in selected:
            try:
                demo_summaries.append({'vulnerability_type': str(getattr(ex, 'vulnerability_type', 'Unknown')), 'score': float(getattr(ex, 'score', 0.0)), 'code_preview': (getattr(ex, 'code', '') or '')[:200], 'fixed_code_preview': (getattr(ex, 'fixed_code', '') or '')[:200]})
            except Exception:
                pass
        rag_meta = {'rag_used': True, 'rag_top_k': int(getattr(self.config, 'rag_top_k', 3)), 'rag_num_demos': len(selected), 'rag_vuln_type_filter': vt, 'rag_index_path': getattr(self.config, 'rag_index_path', None), 'rag_max_added_tokens': max_added, 'rag_added_tokens_est': int(added_tokens), 'rag_demo_summaries': demo_summaries}
        return (new_prompt, rag_meta)

    def _accumulate_usage(self, response) -> None:
        try:
            usage = getattr(response, 'usage', None)
            if not usage:
                return
            pt = getattr(usage, 'prompt_tokens', None)
            ct = getattr(usage, 'completion_tokens', None)
            tt = getattr(usage, 'total_tokens', None)
            if isinstance(pt, int):
                self.stats['prompt_tokens_used'] += pt
            if isinstance(ct, int):
                self.stats['completion_tokens_used'] += ct
            if isinstance(tt, int):
                self.stats['total_tokens_used'] += tt
            elif isinstance(pt, int) and isinstance(ct, int):
                self.stats['total_tokens_used'] += pt + ct
        except Exception:
            return

    def generate_fix(self, func_data: Dict, annotation: Dict) -> Optional[Dict]:
        if annotation.get('label') != 'vulnerable':
            if self.config.verbose:
                print(f'⏭️  跳过非漏洞函数')
            return None
        code_slice = self.slice_builder.build_simplified_contract(func_data)
        if self.config.verbose:
            func_name = func_data.get('function_name', 'unknown')
            contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
            vuln_types = annotation.get('vulnerability_types', [])
            print(f'\n🔧 生成修复代码: {contract_name}.{func_name}')
            print(f"   漏洞类型: {', '.join(vuln_types)}")
        previous_fixed_code = None
        previous_error = None
        previous_full_contract = None
        first_fix_metadata = None
        last_result = None
        for attempt in range(1, self.config.max_fix_attempts + 1):
            if self.config.verbose:
                print(f'\n   尝试 {attempt}/{self.config.max_fix_attempts}...')
            (fixed_code, fix_analysis) = self._generate_fixed_code(func_data=func_data, code_slice=code_slice, annotation=annotation, attempt=attempt, solc_version=func_data.get('solidity_version'), previous_fixed_code=previous_fixed_code, previous_error=previous_error)
            if not fixed_code:
                continue
            verification_result = self._verify_fix(func_data=func_data, fixed_code=fixed_code)
            if attempt == 1 and fix_analysis:
                first_fix_metadata = {'fix_analysis': fix_analysis, 'key_changes': annotation.get('key_changes', []), 'solidity_version_notes': f"Compatible with Solidity {func_data.get('solidity_version', '0.8.0')}"}
            result_metadata = first_fix_metadata if first_fix_metadata else {'fix_analysis': fix_analysis, 'key_changes': annotation.get('key_changes', []), 'solidity_version_notes': f"Compatible with Solidity {func_data.get('solidity_version', '0.8.0')}"}
            result = {'original_code': code_slice, 'fixed_code': fixed_code, 'fix_analysis': result_metadata['fix_analysis'], 'fix_explanation': result_metadata['fix_analysis'], 'vulnerabilities_fixed': annotation.get('vulnerability_types', []), 'verification': verification_result, 'metadata': {'model': self.config.model, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'attempts': attempt, 'original_severity': annotation.get('severity', 0), 'used_error_feedback': previous_fixed_code is not None, 'key_changes': result_metadata['key_changes'], 'solidity_version_notes': result_metadata['solidity_version_notes']}}
            last_result = result
            if self._is_fix_acceptable(verification_result):
                self.stats['successful_fixes'] += 1
                self.stats['fix_attempts_distribution'][attempt] = self.stats['fix_attempts_distribution'].get(attempt, 0) + 1
                if attempt > 1:
                    self.stats['retry_successes'] = self.stats.get('retry_successes', 0) + 1
                if self.config.verbose:
                    print(f'   ✅ 修复成功！')
                    if attempt > 1:
                        print(f'   🔄 通过重试成功（第{attempt}次尝试）')
                        print(f'   📝 使用第一次尝试的修复说明和元数据')
                return result
            previous_fixed_code = fixed_code
            previous_error = verification_result.get('error')
            if self.config.verbose:
                print(f"   ❌ 验证失败: {verification_result.get('error', '未知错误')}")
                if self.config.enable_error_feedback and attempt < self.config.max_fix_attempts:
                    print(f'   🔄 将使用错误信息进行下一次重试')
        self.stats['failed_fixes'] += 1
        if self.config.verbose:
            print(f'   ⛔ 修复失败，已达最大尝试次数 (将记录最后一次尝试)')
        return last_result

    def generate_fix_candidates(self, func_data: Dict, annotation: Dict, n: int=5, prompt_override: Optional[str]=None, system_prompt_override: Optional[str]=None, verify: bool=True, sample_id: Optional[str]=None) -> List[Dict]:
        annotation = annotation or {}
        if prompt_override is not None:
            prompt = str(prompt_override)
            code_slice = ''
        else:
            code_slice = self.slice_builder.build_simplified_contract(func_data)
            solc_version = func_data.get('solidity_version')
            function_name = func_data.get('function_name')
            prompt = self._build_fix_prompt(code_slice=code_slice, annotation=annotation, attempt=1, solc_version=solc_version, function_name=function_name)
        rag_meta: Dict[str, Any] = {'rag_used': False}
        try:
            mode = str(getattr(self.config, 'rag_mode', 'off') or 'off').strip().lower()
            if mode == 'always':
                print(f"\n[RAG] Applying RAG to sample_id={sample_id}, function={func_data.get('function_name', 'unknown')}")
                (prompt, rag_meta) = self._maybe_apply_rag_to_prompt(func_data=func_data, annotation=annotation, prompt=prompt)
                if rag_meta.get('rag_used'):
                    print(f"[RAG] ✓ Successfully applied {rag_meta.get('rag_num_demos', 0)} demos (added ~{rag_meta.get('rag_added_tokens_est', 0)} tokens)")
                else:
                    print(f"[RAG] ✗ Failed: {rag_meta.get('rag_error', 'unknown')}")
            else:
                print(f'[RAG] Mode={mode}, skipping RAG')
        except Exception as e:
            rag_meta = {'rag_used': False, 'rag_error': f'rag_apply_failed: {type(e).__name__}: {e}'}
            print(f'[RAG] ✗ Exception during RAG application: {e}')
        responses = self._call_llm(prompt, self.config.temperature, is_retry=False, n=n, system_prompt_override=system_prompt_override)
        llm_out = getattr(self.config, 'llm_responses_out', None)
        if llm_out:
            out_path = str(llm_out)
            if bool(getattr(self.config, 'llm_responses_append_pid', False)):
                out_path = f'{out_path}.pid{os.getpid()}.jsonl'
            for (i, resp) in enumerate(responses or []):
                _append_jsonl(out_path, {'sample_id': sample_id, 'candidate_id': i, 'contract': func_data.get('contract_path'), 'function': func_data.get('function_name'), 'response': resp})
        if bool(self.config.verbose) or bool(getattr(self.config, 'print_llm_responses', False)):
            print('=' * 80)
            print(f'llm responses (n={n}): ')
            for response in responses:
                print(response)
                print('=' * 80)
        results = []
        for (i, response) in enumerate(responses):
            (fixed_code, fix_analysis) = self._parse_fix_response(response, func_data, is_retry=True)
            result = {'candidate_id': i, 'original_code': code_slice, 'fixed_code': fixed_code, 'fix_analysis': fix_analysis, 'rag': rag_meta, 'verification': {'compiles': False, 'slither_passed': False, 'remaining_issues': [], 'error': None}}
            if verify and fixed_code:
                verification = self._verify_fix(func_data, fixed_code)
                result['verification'] = verification
            results.append(result)
        return results

    def verify_fixed_code(self, func_data: Dict, fixed_code: str) -> Dict:
        return self._verify_fix(func_data, fixed_code)

    def _generate_fixed_code(self, func_data: Dict, code_slice: str, annotation: Dict, attempt: int, solc_version: str, previous_fixed_code: Optional[str]=None, previous_error: Optional[str]=None) -> Tuple[Optional[str], Optional[str]]:
        prompt = self._build_fix_prompt(code_slice=code_slice, annotation=annotation, attempt=attempt, solc_version=solc_version, previous_fixed_code=previous_fixed_code, previous_error=previous_error)
        if self.config.verbose:
            print(f'   📄 构建修复提示词: {prompt}')
            print('=' * 80)
        temperature = self.config.temperature
        is_retry = bool(attempt > 1 and self.config.enable_error_feedback and previous_fixed_code and previous_error)
        if is_retry:
            temperature = self.config.retry_temperature
        responses = self._call_llm(prompt, temperature, is_retry, n=1)
        if not responses:
            return (None, None)
        response = responses[0]
        return self._parse_fix_response(response, func_data, is_retry)

    def _build_fix_prompt(self, code_slice: str, annotation: Dict, attempt: int, solc_version: str, previous_fixed_code: Optional[str]=None, previous_error: Optional[str]=None, function_name: Optional[str]=None) -> str:
        annotation = annotation or {}
        if self.config.evaluation_mode and (not (attempt > 1 and previous_error)):
            removed_comments_code_slice = self._remove_annotation_comments(code_slice)
            return self.prompt_formatter.format_fix_prompt_for_our_models(removed_comments_code_slice, annotation, solc_version, function_name=function_name or '', include_instruction=False)
        if attempt > 1 and self.config.enable_error_feedback and previous_fixed_code and previous_error:
            if '编译失败' in previous_error:
                return self._build_retry_prompt(previous_fixed_code=previous_fixed_code, compile_error=previous_error, annotation=annotation, attempt=attempt, solc_version=solc_version)
            error_summary = self._extract_key_errors(previous_error)
            vulnerability_types = annotation.get('vulnerability_types', [])
            prompt = f
            return prompt
        if self.config.use_rich_fix_prompt:
            return self.prompt_formatter.format_general_fix_prompt_rich(code_slice=code_slice, annotation=annotation, solc_version=solc_version)
        return self.prompt_formatter.format_general_fix_prompt(code_slice=code_slice, annotation=annotation, solc_version=solc_version)

    def _remove_annotation_comments(self, code: str) -> str:
        import re
        code = re.sub('//\\s*<yes>\\s*<report>\\s*[A-Z_]+', '', code)
        code = re.sub('//\\s*<yes>\\s*<report>', '', code)
        code = re.sub('//\\s*VULNERABLE', '', code)
        code = re.sub('//\\s*Vulnerable', '', code)
        lines = code.split('\n')
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped:
                cleaned_lines.append(line)
            elif cleaned_lines:
                if cleaned_lines[-1].strip():
                    cleaned_lines.append('')
        return '\n'.join(cleaned_lines)

    def _build_retry_prompt(self, previous_fixed_code: str, compile_error: str, annotation: Dict, attempt: int, solc_version: str) -> str:
        annotation = annotation or {}
        error_summary = self._extract_key_errors(compile_error)
        vulnerability_types = annotation.get('vulnerability_types', [])
        return self.prompt_formatter.format_retry_prompt(previous_fixed_code=previous_fixed_code, error_summary=error_summary, vulnerability_types=vulnerability_types, solc_version=solc_version)

    def _extract_key_errors(self, compile_error: str) -> str:
        if not compile_error:
            return 'No error details available'
        error_text = compile_error
        if error_text.startswith('编译失败: '):
            error_text = error_text[len('编译失败: '):]
        lines = error_text.strip().split('\n')
        max_lines = self.config.max_error_lines * 2
        if len(lines) <= max_lines:
            return '\n'.join(lines)
        result = '\n'.join(lines[:max_lines])
        result += f'\n... (showing first {max_lines} lines of {len(lines)} total)'
        return result

    def _extract_error_line(self, error_text: str) -> str:
        import re
        match = re.search(':(\\d+):\\d+:', error_text)
        if match:
            return match.group(1)
        return 'unknown'

    def _extract_error_code_line(self, error_text: str) -> str:
        lines = error_text.split('\n')
        for (i, line) in enumerate(lines):
            if 'Error:' in line and i + 1 < len(lines):
                return lines[i + 1].strip()
        return 'unknown'

    def _extract_error_message(self, error_text: str) -> str:
        import re
        match = re.search('Error:\\s*(.+)$', error_text, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return 'unknown'

    def _get_system_prompt(self, is_retry: bool=False) -> str:
        if self.config.evaluation_mode and (not is_retry):
            return self.prompt_formatter.format_fix_instruction()
        if is_retry:
            return self.prompt_formatter.format_retry_system_prompt()
        return self.prompt_formatter.format_general_system_prompt()

    def _get_stop_sequences(self) -> Optional[List[str]]:
        default_stop = ['<|file_sep|>', '<|fim_prefix|>', '<|fim_suffix|>', '<|fim_middle|>', '<|endoftext|>']
        if self.config.stop is None:
            stop = list(default_stop)
        else:
            stop = list(self.config.stop)
        if not stop:
            return None
        seen = set()
        deduped: List[str] = []
        for s in stop:
            if not s or not isinstance(s, str):
                continue
            if s in seen:
                continue
            seen.add(s)
            deduped.append(s)
        if len(deduped) <= 4:
            return deduped
        preferred = '<|endoftext|>'
        if preferred in deduped:
            deduped_wo = [s for s in deduped if s != preferred]
            trimmed = deduped_wo[:3] + [preferred]
        else:
            trimmed = deduped[:4]
        if self.config.verbose:
            print(f'⚠️  stop 序列过长({len(deduped)}), 已自动裁剪为 {len(trimmed)}: {trimmed}')
        return trimmed

    def _should_force_single_n(self) -> bool:
        if bool(getattr(self.config, 'force_single_n', False)):
            return True
        kws = self.config.force_single_n_model_keywords or []
        if not kws:
            return False
        m = (self.config.model or '').lower()
        return any(((kw or '').lower() in m for kw in kws))

    def _is_n_only_one_error(self, e: Exception) -> bool:
        msg = str(e).lower()
        return 'only n = 1' in msg or 'only n=1' in msg or 'invalid n value' in msg or ('range of n should be' in msg) or ("invalid 'n'" in msg) or ('invalid n' in msg and 'n' in msg and ('supported' in msg))

    def _call_llm_n_fallback(self, request_kwargs: Dict, n: int) -> List[str]:
        try:
            nn = int(n)
        except Exception:
            nn = 1
        if nn > 1:
            self.stats['total_requests'] += nn - 1
        results: List[str] = []
        base_extra_body = request_kwargs.get('extra_body') if isinstance(request_kwargs.get('extra_body'), dict) else {}
        base_seed = None
        if isinstance(base_extra_body, dict):
            base_seed = base_extra_body.get('seed')
        workers = max(1, int(getattr(self.config, 'llm_request_workers', 1) or 1))
        nn_int = int(n)

        def _build_rk(i: int) -> Dict:
            rk = dict(request_kwargs)
            rk['n'] = 1
            if isinstance(base_seed, int):
                eb = dict(base_extra_body)
                eb['seed'] = base_seed + i
                rk['extra_body'] = eb
            return rk
        if workers > 1 and nn_int > 1:
            max_workers = min(workers, nn_int)
            responses = [None] * nn_int

            def _one(i: int):
                resp = self.client.chat.completions.create(**_build_rk(i))
                return (i, resp)
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = [ex.submit(_one, i) for i in range(nn_int)]
                for fut in as_completed(futs):
                    (i, resp) = fut.result()
                    responses[i] = resp
            for resp in responses:
                if resp is None:
                    continue
                self._accumulate_usage(resp)
                if getattr(resp, 'choices', None):
                    for choice in resp.choices:
                        results.append(choice.message.content)
        else:
            for i in range(nn_int):
                response = self.client.chat.completions.create(**_build_rk(i))
                self._accumulate_usage(response)
                if getattr(response, 'choices', None):
                    for choice in response.choices:
                        results.append(choice.message.content)
        return results

    def _call_llm_for_evaluation(self, prompt: str, temperature: Optional[float]=None, is_retry: bool=False, n: int=1, system_prompt_override: Optional[str]=None) -> List[str]:
        self.stats['total_requests'] += 1
        if temperature is None:
            temperature = self.config.temperature
        for retry in range(self.config.max_retries):
            try:
                system_prompt = system_prompt_override if system_prompt_override is not None else self._get_system_prompt(is_retry)
                messages = []
                if system_prompt:
                    messages.append({'role': 'system', 'content': system_prompt})
                messages.append({'role': 'user', 'content': prompt})
                if self.config.verbose:
                    print('=' * 80)
                    print('system prompt: \n', system_prompt)
                    print('user prompt: \n', prompt)
                    print('=' * 80)
                extra_body = {}
                if self.config.seed is not None:
                    extra_body['seed'] = self.config.seed
                extra_body = _maybe_add_reasoning_controls(extra_body, self.config)
                request_kwargs = {'model': self.config.model, 'messages': messages, 'temperature': temperature, 'n': n}
                if self.config.top_p is not None:
                    request_kwargs['top_p'] = self.config.top_p
                if self.config.max_tokens is not None:
                    request_kwargs['max_tokens'] = self.config.max_tokens
                if self.config.presence_penalty is not None:
                    request_kwargs['presence_penalty'] = self.config.presence_penalty
                if self.config.frequency_penalty is not None:
                    request_kwargs['frequency_penalty'] = self.config.frequency_penalty
                if extra_body:
                    request_kwargs['extra_body'] = extra_body
                desired_n = int(n) if isinstance(n, int) else 1
                if desired_n > 1 and self._should_force_single_n():
                    if self.config.verbose:
                        print(f"ℹ️  Model '{self.config.model}' 命中 force_single_n_model_keywords，将 n={desired_n} 改为循环调用 {desired_n} 次（每次 n=1）")
                    request_kwargs['n'] = 1
                    results = self._call_llm_n_fallback(request_kwargs, n=desired_n)
                else:
                    try:
                        response = self.client.chat.completions.create(**request_kwargs)
                        self._accumulate_usage(response)
                        results = []
                        for choice in response.choices:
                            results.append(choice.message.content)
                    except Exception as e:
                        if self.config.allow_n_fallback and isinstance(n, int) and (n > 1) and self._is_n_only_one_error(e):
                            if self.config.verbose:
                                print(f'⚠️  Provider 不支持 n={n}，自动 fallback 为循环调用 n 次（每次 n=1）')
                            results = self._call_llm_n_fallback(request_kwargs, n=n)
                        else:
                            raise
                if self.config.verbose:
                    print('\n' + '=' * 80)
                    print(f'🤖 LLM 修复响应 (n={n}):')
                    print('=' * 80)
                    for (i, content) in enumerate(results):
                        print(f'--- Candidate {i + 1} ---')
                        print(content[:500] + '...' if len(content) > 500 else content)
                    print('=' * 80 + '\n')
                return results
            except Exception as e:
                self.stats['api_errors'] += 1
                try:
                    eb = request_kwargs.get('extra_body') if isinstance(request_kwargs.get('extra_body'), dict) else {}
                    (eb2, did) = _strip_reasoning_controls_on_error(eb, e)
                    if did:
                        request_kwargs['extra_body'] = eb2
                        print(f'LLM API调用失败：reasoning 控制参数可能不被支持，已移除并重试 ({retry + 1}/{self.config.max_retries})')
                        continue
                except Exception:
                    pass
                print(f'LLM API调用失败 (重试 {retry + 1}/{self.config.max_retries}): {e}')
                if retry < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (retry + 1))
                else:
                    return []
        return []

    def _call_llm(self, prompt: str, temperature: Optional[float]=None, is_retry: bool=False, n: int=1, system_prompt_override: Optional[str]=None) -> List[str]:
        if self.config.evaluation_mode:
            return self._call_llm_for_evaluation(prompt, temperature, is_retry, n, system_prompt_override=system_prompt_override)
        self.stats['total_requests'] += 1
        if temperature is None:
            temperature = self.config.temperature
        for retry in range(self.config.max_retries):
            try:
                system_prompt = system_prompt_override if system_prompt_override is not None else self._get_system_prompt(is_retry)
                messages = []
                if system_prompt:
                    messages.append({'role': 'system', 'content': system_prompt})
                messages.append({'role': 'user', 'content': prompt})
                extra_body = {}
                if self.config.seed is not None:
                    extra_body['seed'] = self.config.seed
                extra_body = _maybe_add_reasoning_controls(extra_body, self.config)
                request_kwargs = {'model': self.config.model, 'messages': messages, 'temperature': temperature, 'n': n, 'response_format': {'type': 'json_object'} if not is_retry and (not self.config.evaluation_mode) else None}
                if self.config.top_p is not None:
                    request_kwargs['top_p'] = self.config.top_p
                if self.config.max_tokens is not None:
                    request_kwargs['max_tokens'] = self.config.max_tokens
                if self.config.presence_penalty is not None:
                    request_kwargs['presence_penalty'] = self.config.presence_penalty
                if self.config.frequency_penalty is not None:
                    request_kwargs['frequency_penalty'] = self.config.frequency_penalty
                if extra_body:
                    request_kwargs['extra_body'] = extra_body
                desired_n = int(n) if isinstance(n, int) else 1
                if desired_n > 1 and self._should_force_single_n():
                    if self.config.verbose:
                        print(f"ℹ️  Model '{self.config.model}' 命中 force_single_n_model_keywords，将 n={desired_n} 改为循环调用 {desired_n} 次（每次 n=1）")
                    request_kwargs['n'] = 1
                    results = self._call_llm_n_fallback(request_kwargs, n=desired_n)
                else:
                    try:
                        response = self.client.chat.completions.create(**request_kwargs)
                        self._accumulate_usage(response)
                        results = []
                        for choice in response.choices:
                            results.append(choice.message.content)
                    except Exception as e:
                        if self.config.allow_n_fallback and isinstance(n, int) and (n > 1) and self._is_n_only_one_error(e):
                            if self.config.verbose:
                                print(f'⚠️  Provider 不支持 n={n}，自动 fallback 为循环调用 n 次（每次 n=1）')
                            results = self._call_llm_n_fallback(request_kwargs, n=n)
                        else:
                            raise
                if self.config.verbose:
                    print('\n' + '=' * 80)
                    print(f'🤖 LLM 修复响应 (n={n}):')
                    print('=' * 80)
                    for (i, content) in enumerate(results):
                        print(f'--- Candidate {i + 1} ---')
                        print(content[:500] + '...' if len(content) > 500 else content)
                    print('=' * 80 + '\n')
                return results
            except Exception as e:
                self.stats['api_errors'] += 1
                try:
                    eb = request_kwargs.get('extra_body') if isinstance(request_kwargs.get('extra_body'), dict) else {}
                    (eb2, did) = _strip_reasoning_controls_on_error(eb, e)
                    if did:
                        request_kwargs['extra_body'] = eb2
                        print(f'LLM API调用失败：reasoning 控制参数可能不被支持，已移除并重试 ({retry + 1}/{self.config.max_retries})')
                        continue
                except Exception:
                    pass
                print(f'LLM API调用失败 (重试 {retry + 1}/{self.config.max_retries}): {e}')
                if retry < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (retry + 1))
                else:
                    return []
        return []

    def _parse_fix_response(self, response: str, func_data: Dict, is_retry: bool=False) -> Tuple[Optional[str], Optional[str]]:
        if is_retry:
            fixed_code = self._extract_code_from_response(response)
            if fixed_code:
                if self.config.verbose:
                    print(f'   ✅ 重试响应：成功提取修复代码，长度: {len(fixed_code)} 字符')
                return (fixed_code, '修复代码（编译错误重试）')
            else:
                if self.config.verbose:
                    print(f'   ⚠️  重试响应：无法提取修复代码')
                    print(f'   原始响应: {response[:500]}')
                return (None, None)
        try:
            json_str = self._extract_json_from_response(response)
            if not json_str:
                if self.config.verbose:
                    print(f'   ⚠️  无法从响应中提取JSON，尝试直接提取代码')
                    print(f'   原始响应前500字符: {response[:500]}')
                fixed_code = self._extract_code_from_response(response)
                if fixed_code:
                    return (fixed_code, '修复代码（无详细说明）')
                print(f'无法从响应中提取修复代码')
                return (None, None)
            if self.config.verbose:
                print(f'   ✅ 提取到JSON，长度: {len(json_str)} 字符')
                print(f'   JSON预览: {json_str[:200]}...')
            data = json.loads(json_str)
            fixed_code = data.get('fixed_code', '')
            fix_analysis = data.get('fix_analysis', '')
            fixed_code = self._clean_code(fixed_code)
            if not fixed_code:
                print('修复代码为空')
                return (None, None)
            if self.config.verbose:
                print(f'   ✅ 成功解析修复代码，长度: {len(fixed_code)} 字符')
            return (fixed_code, fix_analysis)
        except json.JSONDecodeError as e:
            print(f'JSON解析失败: {e}')
            if self.config.verbose:
                print(f"   原始JSON: {(json_str[:500] if json_str else 'None')}")
                print(f'   错误位置: 第{e.lineno}行，第{e.colno}列')
                if json_str:
                    error_pos = e.pos if hasattr(e, 'pos') else 0
                    start = max(0, error_pos - 50)
                    end = min(len(json_str), error_pos + 50)
                    print(f'   错误上下文: ...{json_str[start:end]}...')
            fixed_code = self._extract_code_from_response(response)
            if fixed_code:
                return (fixed_code, '修复代码（解析JSON失败）')
            return (None, None)
        except Exception as e:
            print(f'解析修复响应时出错: {e}')
            return (None, None)

    def _extract_json_from_response(self, response: str) -> Optional[str]:
        import re
        json_code_block = re.search('```(?:json)?\\s*(\\{.*?\\})\\s*```', response, re.DOTALL)
        if json_code_block:
            return json_code_block.group(1)
        json_match = re.search('\\{(?:[^{}"\\[\\]]|"(?:\\\\.|[^"\\\\])*"|\\[(?:[^\\[\\]"\\\']|"(?:\\\\.|[^"\\\\])*"|\\\'(?:\\\\.|[^\\\'\\\\])*\\\')*\\]|\\{(?:[^{}"\\[\\]]|"(?:\\\\.|[^"\\\\])*"|\\[(?:[^\\[\\]"\\\']|"(?:\\\\.|[^"\\\\])*"|\\\'(?:\\\\.|[^\\\'\\\\])*\\\')*\\])*\\})*\\}', response, re.DOTALL)
        if json_match:
            return json_match.group(0)
        response_stripped = response.strip()
        if response_stripped.startswith('{') and response_stripped.endswith('}'):
            return response_stripped
        return None

    def _extract_code_from_response(self, response: str) -> Optional[str]:
        import re
        code_block = re.search('```(?:solidity)?\\s*(.*?)\\s*```', response, re.DOTALL)
        if code_block:
            return code_block.group(1).strip()
        return None

    def _clean_code(self, code: str) -> str:
        import re
        code = re.sub('```(?:solidity)?', '', code)
        code = code.strip()
        return code

    def _verify_fix(self, func_data: Dict, fixed_code: str) -> Dict:
        result = {'compiles': False, 'slither_passed': False, 'remaining_issues': [], 'error': None, 'full_contract': None, 'mythril_passed': True, 'mythril_issues': [], 'mythril_error': None}
        if self.config.enable_compilation_check:
            (compiles, compile_error, full_contract) = self._check_compilation(func_data, fixed_code)
            result['compiles'] = compiles
            result['full_contract'] = full_contract
            if not compiles:
                result['error'] = f'编译失败: {compile_error}'
                self.stats['compilation_failures'] += 1
                if self.config.enable_error_feedback:
                    self.stats['error_feedback_used'] = self.stats.get('error_feedback_used', 0) + 1
                return result
        else:
            result['compiles'] = True
            result['full_contract'] = self.slice_builder.rebuild_full_contract(func_data, fixed_code)
        if self.config.enable_slither_check:
            (slither_passed, remaining_issues, ir_sim, ir_change_rate, ir_available) = self._check_with_slither(func_data, fixed_code)
            result['slither_passed'] = slither_passed
            result['remaining_issues'] = remaining_issues
            result['ir_available'] = bool(ir_available)
            result['ir_sim'] = float(ir_sim)
            result['ir_change_rate'] = float(ir_change_rate)
            if not slither_passed:
                result['error'] = f"Slither检测到问题: {', '.join(remaining_issues)}"
                self.stats['slither_check_failures'] += 1
        else:
            result['slither_passed'] = True
        if self.config.enable_mythril_check:
            full_contract = result.get('full_contract')
            if isinstance(full_contract, str) and full_contract.strip():
                try:
                    if self.config.verbose:
                        sev_s = None
                        try:
                            sev_s = ', '.join(list(self.config.mythril_severities)) if self.config.mythril_severities is not None else 'high, medium'
                        except Exception:
                            sev_s = 'high, medium'
                        print(f'   🧪 开始Mythril检查 (timeout={self.config.mythril_timeout}s, severities={sev_s})')
                    mr = self.mythril_manager.analyze_source(contract_src=full_contract, timeout=int(self.config.mythril_timeout), severities=self.config.mythril_severities if self.config.mythril_severities is not None else ('high', 'medium'), max_issues=50)
                    mr_error = str(mr.error or '')
                    uncertain = False
                    if mr_error:
                        err_l = mr_error.lower()
                        uncertain = any((k in err_l for k in ['mythril_timeout', 'mythril_not_found', 'contract_not_found', 'mythril_error', 'mythril_rc=']))
                    if bool(getattr(self.config, 'mythril_uncertain_as_pass', True)) and uncertain:
                        result['mythril_passed'] = True
                    else:
                        result['mythril_passed'] = bool(mr.passed)
                    result['mythril_issues'] = mr.issues
                    result['mythril_error'] = mr.error
                    if self.config.verbose:
                        if mr.passed:
                            print(f'   ✅ Mythril通过 (issues=0)')
                        else:
                            print(f'   ❌ Mythril未通过 (issues={mr.issue_count})')
                    if not mr.passed:
                        msg = 'Mythril检测到问题: ' + '; '.join(mr.issues[:10])
                        result['error'] = msg
                except Exception as e:
                    result['mythril_passed'] = True
                    result['mythril_error'] = f'{type(e).__name__}: {e}'
                    if self.config.verbose:
                        print(f'   ⚠️  Mythril检查出错: {type(e).__name__}: {e}，跳过')
            else:
                result['mythril_passed'] = True
                if self.config.verbose:
                    print('   ⚠️  无法构建完整合约，跳过Mythril检查')
        return result

    def _check_compilation(self, func_data: Dict, fixed_code: str) -> Tuple[bool, Optional[str], Optional[str]]:
        full_contract = self.slice_builder.rebuild_full_contract(func_data, fixed_code)
        if full_contract is None:
            msg = '无法构建完整合约（full_contract=None）'
            if bool(getattr(self.config, 'strict_verification', False)):
                return (False, msg, None)
            return (True, None, None)
        try:
            import tempfile
            (fd, temp_file) = tempfile.mkstemp(suffix='.sol')
            if self.config.verbose:
                print(f'   📄 创建临时文件: {temp_file}')
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(full_contract)
                solc_path = self.slither_manager.setup_solc_version(temp_file)
                if not solc_path:
                    if self.config.verbose:
                        print('   ⚠️  无法设置编译器版本，尝试使用默认solc')
                    solc_path = 'solc'
                elif solc_path == 'SOLCX_ENV':
                    solc_path = 'solc'
                if self.config.verbose:
                    print(f'   🔨 使用编译器: {solc_path}')
                result = subprocess.run([solc_path, '--bin', temp_file], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    if self.config.verbose:
                        print(f'   ✅ 编译成功')
                    return (True, None, full_contract)
                else:
                    if self.config.verbose:
                        print(f'   ❌ 编译失败: {result.stderr[:200]}')
                    return (False, result.stderr, full_contract)
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    if self.config.verbose:
                        print(f'   🗑️  清理临时文件: {temp_file}')
        except FileNotFoundError:
            if self.config.verbose:
                print('   ⚠️  未找到solc编译器')
            if bool(getattr(self.config, 'strict_verification', False)):
                return (False, '未找到solc编译器', full_contract)
            return (True, None, full_contract)
        except subprocess.TimeoutExpired:
            return (False, '编译超时', full_contract)
        except Exception as e:
            if self.config.verbose:
                print(f'   ⚠️  编译检查出错: {e}，跳过')
            if bool(getattr(self.config, 'strict_verification', False)):
                return (False, f'编译检查异常: {type(e).__name__}: {e}', full_contract)
            return (True, None, full_contract)

    def _check_with_slither(self, func_data: Dict, fixed_code: str) -> Tuple[bool, List[str], float, float, bool]:
        try:
            full_contract = self.slice_builder.rebuild_full_contract(func_data, fixed_code)
            if full_contract is None:
                if self.config.verbose:
                    print('   ⚠️  无法构建完整合约')
                if bool(getattr(self.config, 'strict_verification', False)):
                    return (False, ['无法构建完整合约（full_contract=None）'], 0.0, 0.0, False)
                return (True, [], 0.0, 0.0, False)
            import tempfile
            (fd, temp_file) = tempfile.mkstemp(suffix='.sol')
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(full_contract)
                slither_passed = False
                critical_issues: List[str] = []
                ir_sim = 0.0
                ir_change_rate = 0.0
                ir_available = False
                with self.slither_manager.analyze_contract(temp_file) as slither:
                    if slither:
                        try:
                            ref_ops = self._get_reference_ir_ops(func_data)
                            cur_ops = self._extract_function_ir_ops(slither, str(func_data.get('function_name') or ''))
                            if ref_ops and cur_ops:
                                ir_available = True
                                ir_sim = float(difflib.SequenceMatcher(a=ref_ops, b=cur_ops).ratio())
                                ir_change_rate = float(1.0 - ir_sim)
                        except Exception:
                            ir_available = False
                            ir_sim = 0.0
                            ir_change_rate = 0.0
                        try:
                            if hasattr(slither, 'run_detectors'):
                                slither.run_detectors()
                        except Exception:
                            pass
                        try:
                            critical_issues.extend(collect_slither_issues(slither, severities=('high', 'medium', 'low')))
                        except Exception:
                            pass
                        slither_passed = len(critical_issues) == 0
                    else:
                        if self.config.verbose:
                            print('   ⚠️  Slither 未能解析合约')
                        if bool(getattr(self.config, 'strict_verification', False)):
                            return (False, ['Slither 未能解析合约（slither=None）'], 0.0, 0.0, False)
                        return (True, [], 0.0, 0.0, False)
                return (slither_passed, critical_issues, ir_sim, ir_change_rate, ir_available)
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
        except FileNotFoundError:
            if self.config.verbose:
                print('   ⚠️  未找到Slither，跳过Slither检查')
            if bool(getattr(self.config, 'strict_verification', False)):
                return (False, ['未找到Slither'], 0.0, 0.0, False)
            return (True, [], 0.0, 0.0, False)
        except subprocess.TimeoutExpired:
            if self.config.verbose:
                print('   ⚠️  Slither检查超时')
            if bool(getattr(self.config, 'strict_verification', False)):
                return (False, ['Slither检查超时'], 0.0, 0.0, False)
            return (True, [], 0.0, 0.0, False)
        except Exception as e:
            if self.config.verbose:
                print(f'   ⚠️  Slither检查出错: {e}，跳过')
            if bool(getattr(self.config, 'strict_verification', False)):
                return (False, [f'Slither检查异常: {type(e).__name__}: {e}'], 0.0, 0.0, False)
            return (True, [], 0.0, 0.0, False)

    def _reference_ir_cache_key(self, func_data: Dict) -> str:
        return '|'.join([str(func_data.get('contract_path') or ''), str(func_data.get('function_name') or ''), str(func_data.get('start_line') or ''), str(func_data.get('end_line') or ''), str(func_data.get('solidity_version') or '')])

    def _get_reference_ir_ops(self, func_data: Dict) -> List[str]:
        k = self._reference_ir_cache_key(func_data)
        cached = self._reference_ir_cache.get(k)
        if cached is not None:
            return cached
        original_code = str(func_data.get('function_code') or '')
        full_contract = self.slice_builder.rebuild_full_contract(func_data, original_code)
        if not isinstance(full_contract, str) or not full_contract.strip():
            self._reference_ir_cache[k] = []
            return []
        (fd, temp_file) = tempfile.mkstemp(suffix='.sol')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(full_contract)
            with self.slither_manager.analyze_contract(temp_file) as slither:
                if not slither:
                    self._reference_ir_cache[k] = []
                    return []
                ops = self._extract_function_ir_ops(slither, str(func_data.get('function_name') or ''))
                self._reference_ir_cache[k] = ops
                return ops
        except Exception:
            self._reference_ir_cache[k] = []
            return []
        finally:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception:
                pass

    def _extract_function_ir_ops(self, slither, function_name: str) -> List[str]:
        if not slither or not function_name:
            return []
        ops: List[str] = []
        try:
            for contract in getattr(slither, 'contracts', []) or []:
                funcs = getattr(contract, 'functions_declared', None) or getattr(contract, 'functions', None) or []
                for fn in funcs:
                    if getattr(fn, 'name', None) != function_name:
                        continue
                    for node in getattr(fn, 'nodes', []) or []:
                        for ir in getattr(node, 'irs', []) or []:
                            ops.append(type(ir).__name__)
                    if ops:
                        return ops
        except Exception:
            return []
        return ops

    def _is_fix_acceptable(self, verification_result: Dict) -> bool:
        if not verification_result.get('compiles', False):
            return False
        if self.config.enable_slither_check:
            if not verification_result.get('slither_passed', False):
                return False
        if self.config.enable_mythril_check:
            if not verification_result.get('mythril_passed', True):
                return False
        return True

    def batch_generate_fixes(self, annotated_data: List[Tuple[Dict, Dict]], progress_callback=None) -> List[Tuple[Dict, Dict, Optional[Dict]]]:
        results = []
        vulnerable_data = [(func_data, annotation) for (func_data, annotation) in annotated_data if annotation and annotation.get('label') == 'vulnerable']
        total = len(vulnerable_data)
        if total == 0:
            print('没有需要修复的漏洞函数')
            return results
        print(f'开始批量生成修复代码，共 {total} 个漏洞函数...')
        for (i, (func_data, annotation)) in enumerate(vulnerable_data, 1):
            if progress_callback:
                progress_callback(i, total)
            func_name = func_data.get('function_name', 'unknown')
            print(f'\n[{i}/{total}] 修复函数: {func_name}...')
            fix_result = self.generate_fix(func_data, annotation)
            results.append((func_data, annotation, fix_result))
            if i < total:
                time.sleep(1)
        print(f'\n修复完成！')
        self.print_stats()
        return results

    def print_stats(self):
        print('\n' + '=' * 60)
        print('修复统计信息:')
        print(f"  总请求数: {self.stats['total_requests']}")
        print(f"  成功修复: {self.stats['successful_fixes']}")
        print(f"  失败修复: {self.stats['failed_fixes']}")
        print(f"  编译失败: {self.stats['compilation_failures']}")
        print(f"  Slither检查失败: {self.stats['slither_check_failures']}")
        print(f"  API错误: {self.stats['api_errors']}")
        print(f"  总Token使用: {self.stats['total_tokens_used']}")
        if 'retry_successes' in self.stats:
            print(f"  重试成功: {self.stats['retry_successes']}")
        if 'error_feedback_used' in self.stats:
            print(f"  错误反馈使用: {self.stats['error_feedback_used']}")
        if self.stats['successful_fixes'] > 0:
            avg_tokens = self.stats['total_tokens_used'] / self.stats['successful_fixes']
            print(f'  平均Token/次: {avg_tokens:.1f}')
            success_rate = self.stats['successful_fixes'] / (self.stats['successful_fixes'] + self.stats['failed_fixes']) * 100
            print(f'  成功率: {success_rate:.1f}%')
        if self.stats['fix_attempts_distribution']:
            print('\n  修复尝试次数分布:')
            for (attempts, count) in sorted(self.stats['fix_attempts_distribution'].items()):
                percentage = count / self.stats['successful_fixes'] * 100 if self.stats['successful_fixes'] > 0 else 0
                print(f'    {attempts}次尝试: {count}个函数 ({percentage:.1f}%)')
        print('=' * 60)
if __name__ == '__main__':
    import os
    with open('config.models.json', 'r') as f:
        config_data = json.load(f)
        model_configs = config_data.get('models', [])
    model_name = 'deepseek-char'
    for model_config in model_configs:
        if model_config['model'] == model_name:
            api_key = model_config['api_key']
            base_url = model_config['base_url']
            break
    if not api_key:
        print('\n❌ 错误: 未设置 OPENAI_API_KEY 环境变量')
        print("请设置: export OPENAI_API_KEY='your-api-key'")
    print(f'\n✅ API配置: {model_name}')
    config = FixerConfig(api_key=api_key, base_url=base_url, model=model_name, temperature=0.2, verbose=True, enable_compilation_check=False, enable_slither_check=False)
    fixer = LLMFixer(config)
    mock_func_data = {'function_name': 'withdraw', 'function_code': 'function withdraw(uint amount) public {\n    msg.sender.call{value: amount}("");\n    balances[msg.sender] -= amount;\n}', 'contract_context': {'contract_name': 'Vault', 'state_variables': [{'code': 'mapping(address => uint) public balances;'}]}, 'solidity_version': '0.8.0'}
    mock_annotation = {'label': 'vulnerable', 'analysis': 'This function is vulnerable to reentrancy attacks.', 'reasoning': 'The function makes an external call before updating the state.', 'vulnerability_types': ['reentrancy-eth'], 'severity': 9.0, 'confidence': 0.95}
    print('测试修复器...')
    result = fixer.generate_fix(mock_func_data, mock_annotation)
    if result:
        print('\n修复结果:')
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print('修复失败')
