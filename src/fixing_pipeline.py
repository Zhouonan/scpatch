import os
import sys
import json
import argparse
import asyncio
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from tqdm import tqdm
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
from src.database.db_manager import DBManager
from src.tools.llm_fixer import LLMFixer, FixerConfig
from src.tools.mythril_manager import MythrilManager
import time
from datetime import datetime
from src.tools.label_annotation_builder import LabelAnnotationBuilder

class FixingPipeline:

    def __init__(self, db_manager: DBManager, fixer: LLMFixer, save_interval: int=10, concurrency: int=5, log_failures: bool=False, failure_log_dir: str='failure_logs', output_json: bool=False, output_json_dir: str='fix_json_outputs', skip_existing_json: bool=True, output_json_mode: str='failed', output_json_full: bool=False, use_label_annotation: bool=False, enable_mythril_check: bool=False, mythril_timeout: int=120, mythril_severities: Optional[List[str]]=None, mythril_bin: str='myth'):
        self.db_manager = db_manager
        self.fixer = fixer
        self.save_interval = save_interval
        self.concurrency = concurrency
        self.log_failures = log_failures
        self.failure_log_dir = Path(failure_log_dir)
        self.output_json = output_json
        self.output_json_dir = Path(output_json_dir)
        self.skip_existing_json = skip_existing_json
        self.output_json_mode = output_json_mode
        self.output_json_full = output_json_full
        self.use_label_annotation = use_label_annotation
        self.enable_mythril_check = enable_mythril_check
        self.mythril_timeout = mythril_timeout
        self.mythril_severities = mythril_severities
        self.mythril_manager = MythrilManager(debug=fixer.config.verbose, mythril_bin=mythril_bin)
        self._label_annot_builder = LabelAnnotationBuilder()
        if self.log_failures:
            self.failure_log_dir.mkdir(parents=True, exist_ok=True)
        if self.output_json:
            self.output_json_dir.mkdir(parents=True, exist_ok=True)

    async def process_item(self, func_data: Dict, semaphore: asyncio.Semaphore):
        func_name = func_data.get('function_name', 'unknown')
        contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
        annotation = func_data.get('llm_audit')
        if not annotation:
            if self.use_label_annotation:
                built = self._label_annot_builder.build(func_data)
                if built:
                    annotation = built.annotation
                else:
                    return (func_data, None, 'no_annotation')
            else:
                return (func_data, None, 'no_annotation')
        if annotation.get('label') != 'vulnerable':
            return (func_data, None, 'safe')
        async with semaphore:
            fix_result = await asyncio.to_thread(self.fixer.generate_fix, func_data, annotation)
            return (func_data, fix_result, 'processed')

    async def run_async(self, functions_data: List[Dict]):
        total = len(functions_data)
        print(f'\n[3/4] 开始LLM修复（并发数: {self.concurrency}, 每{self.save_interval}条保存一次）...')
        fixed_count = 0
        failed_count = 0
        skipped_count = 0
        buffer = []
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self.process_item(func_data, semaphore) for func_data in functions_data]
        with tqdm(total=total, desc='修复进度') as pbar:
            for coro in asyncio.as_completed(tasks):
                (func_data, fix_result, status) = await coro
                func_name = func_data.get('function_name', 'unknown')
                contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
                if status == 'no_annotation':
                    skipped_count += 1
                    pbar.set_postfix({'success': fixed_count, 'failed': failed_count, 'skipped': skipped_count, 'current': f'SKIP: {contract_name}.{func_name}'})
                elif status == 'safe':
                    skipped_count += 1
                    pbar.set_postfix({'success': fixed_count, 'failed': failed_count, 'skipped': skipped_count, 'current': f'SAFE: {contract_name}.{func_name}'})
                elif status == 'processed':
                    if fix_result:
                        func_data['llm_fix'] = fix_result
                        buffer.append(func_data)
                        try:
                            self._augment_verification_with_tools(func_data, fix_result)
                        except Exception as e:
                            if self.fixer.config.verbose:
                                print(f'\n[WARN] 工具校验汇总失败: {type(e).__name__}: {e}')
                        verification = fix_result.get('verification', {}) or {}
                        is_success = verification.get('compiles', False)
                        tools_passed = verification.get('tools_passed')
                        if isinstance(tools_passed, bool):
                            is_success = is_success and tools_passed
                        elif self.fixer.config.enable_slither_check:
                            is_success = is_success and verification.get('slither_passed', False)
                        if is_success:
                            fixed_count += 1
                            current_status = f'{contract_name}.{func_name}'
                            func_data['_fix_status'] = 'success'
                            func_data['_fix_failure_reason'] = None
                        else:
                            failed_count += 1
                            current_status = f'FAILED: {contract_name}.{func_name}'
                            func_data['_fix_status'] = 'failed_verification'
                            func_data['_fix_failure_reason'] = 'verification_failed'
                            if self.log_failures:
                                self._save_failure_log(func_data, fix_result, 'Verification Failed')
                        if self.output_json and self._should_output_json(func_data):
                            try:
                                self._save_fix_json(func_data)
                            except Exception as e:
                                if self.fixer.config.verbose:
                                    print(f'\n[WARN] 保存json失败: {e}')
                        pbar.set_postfix({'success': fixed_count, 'failed': failed_count, 'skipped': skipped_count, 'current': current_status})
                    else:
                        failed_count += 1
                        func_data['llm_fix'] = {}
                        func_data['_fix_status'] = 'failed_llm'
                        func_data['_fix_failure_reason'] = 'llm_generation_failed'
                        if self.log_failures:
                            self._save_failure_log(func_data, None, 'LLM Generation Failed')
                        if self.output_json and self._should_output_json(func_data):
                            try:
                                self._save_fix_json(func_data)
                            except Exception as e:
                                if self.fixer.config.verbose:
                                    print(f'\n[WARN] 保存json失败: {e}')
                        pbar.set_postfix({'success': fixed_count, 'failed': failed_count, 'skipped': skipped_count, 'current': f'ERROR: {contract_name}.{func_name}'})
                if len(buffer) >= self.save_interval:
                    print(f'\n  [保存中] 保存 {len(buffer)} 条修复结果到数据库...')
                    self._save_fixes(buffer)
                    buffer.clear()
                pbar.update(1)
        if buffer:
            print(f'\n  [保存中] 保存最后 {len(buffer)} 条修复结果到数据库...')
            self._save_fixes(buffer)
        return (fixed_count, failed_count, skipped_count)

    def run(self, dataset_types: Optional[List[str]]=None, dataset_names: Optional[List[str]]=None, limit: Optional[int]=None, only_vulnerable: bool=True, skip_already_fixed: bool=True, skip_fixed_scope: str='model', min_severity: float=0.0, vuln_types: Optional[List[str]]=None):
        print('=' * 80)
        print('LLM修复流水线 - 阶段2')
        print('=' * 80)
        print('\n[1/4] 查询数据库...')
        if self.use_label_annotation:
            functions = self._query_functions_label_based(dataset_types=dataset_types, dataset_names=dataset_names, only_vulnerable=only_vulnerable, skip_already_fixed=skip_already_fixed, skip_fixed_scope=skip_fixed_scope, fixed_model=self.fixer.config.model if skip_fixed_scope == 'model' else None, min_severity=min_severity, vuln_types=vuln_types)
        else:
            functions = self._query_functions(dataset_types=dataset_types, dataset_names=dataset_names, only_vulnerable=only_vulnerable, skip_already_fixed=skip_already_fixed, skip_fixed_scope=skip_fixed_scope, fixed_model=self.fixer.config.model if skip_fixed_scope == 'model' else None, min_severity=min_severity, vuln_types=vuln_types)
        if not functions:
            print('没有需要修复的数据')
            return
        if limit:
            functions = functions[:limit]
        total = len(functions)
        print(f'找到 {total} 条需要修复的数据')
        print('\n[2/4] 准备修复数据...')
        functions_data = self._prepare_function_data(functions)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            (fixed_count, failed_count, skipped_count) = loop.run_until_complete(self.run_async(functions_data))
        finally:
            loop.close()
        print('\n[4/4] 修复完成！')
        print(f"\n{'=' * 80}")
        print(f'修复结果统计:')
        print(f'  总处理数: {total}')
        print(f'  成功修复: {fixed_count}')
        print(f'  失败修复: {failed_count}')
        print(f'  跳过数量: {skipped_count}')
        if fixed_count + failed_count > 0:
            print(f'  成功率: {fixed_count / (fixed_count + failed_count) * 100:.1f}%')
        print(f"{'=' * 80}")
        self.fixer.print_stats()

    def _query_functions(self, dataset_types: Optional[List[str]], dataset_names: Optional[List[str]], only_vulnerable: bool, skip_already_fixed: bool, skip_fixed_scope: str, fixed_model: Optional[str], min_severity: float, vuln_types: Optional[List[str]]=None) -> List:
        session = self.db_manager.get_session()
        try:
            from src.database.models import SmartContractFunction
            from src.database.models_fix import VulnerabilityFix
            from sqlalchemy import cast, String
            query = session.query(SmartContractFunction)
            if dataset_types:
                query = query.filter(SmartContractFunction.dataset_type.in_(dataset_types))
            if dataset_names:
                query = query.filter(SmartContractFunction.dataset_name.in_(dataset_names))
            query = query.filter(SmartContractFunction.llm_audit.isnot(None))
            query = query.filter(cast(SmartContractFunction.llm_audit, String) != 'null')
            functions = query.all()
            fixed_function_ids = set()
            if skip_already_fixed:
                fixed_query = session.query(VulnerabilityFix.function_id).distinct()
                if skip_fixed_scope == 'model' and fixed_model:
                    fixed_query = fixed_query.filter(VulnerabilityFix.model_name == fixed_model)
                fixed_records = fixed_query.all()
                fixed_function_ids = {record[0] for record in fixed_records}
            filtered_functions = []
            resolved_filters = self._resolve_vuln_type_filters(vuln_types)
            for func in functions:
                if skip_already_fixed and func.id in fixed_function_ids:
                    continue
                if only_vulnerable:
                    if func.llm_audit and func.llm_audit.get('label') != 'vulnerable':
                        continue
                if min_severity > 0:
                    severity = 0
                    if func.llm_audit:
                        severity = func.llm_audit.get('severity', 0)
                    if severity < min_severity:
                        continue
                if resolved_filters:
                    func_types = self._extract_types_from_record(func)
                    if not func_types & resolved_filters:
                        continue
                filtered_functions.append(func)
            return filtered_functions
        finally:
            session.close()

    def _query_functions_label_based(self, dataset_types: Optional[List[str]], dataset_names: Optional[List[str]], only_vulnerable: bool, skip_already_fixed: bool, skip_fixed_scope: str, fixed_model: Optional[str], min_severity: float, vuln_types: Optional[List[str]]=None) -> List:
        session = self.db_manager.get_session()
        try:
            from src.database.models import SmartContractFunction
            from src.database.models_fix import VulnerabilityFix
            query = session.query(SmartContractFunction)
            if dataset_types:
                query = query.filter(SmartContractFunction.dataset_type.in_(dataset_types))
            if dataset_names:
                query = query.filter(SmartContractFunction.dataset_name.in_(dataset_names))
            if only_vulnerable:
                query = query.filter(SmartContractFunction.is_vulnerable == True)
            if min_severity and min_severity > 0:
                query = query.filter(SmartContractFunction.severity >= float(min_severity))
            functions = query.all()
            fixed_function_ids = set()
            if skip_already_fixed:
                fixed_query = session.query(VulnerabilityFix.function_id).distinct()
                if skip_fixed_scope == 'model' and fixed_model:
                    fixed_query = fixed_query.filter(VulnerabilityFix.model_name == fixed_model)
                fixed_records = fixed_query.all()
                fixed_function_ids = {record[0] for record in fixed_records}
            filtered = []
            resolved_filters = self._resolve_vuln_type_filters(vuln_types)
            for f in functions:
                if skip_already_fixed and f.id in fixed_function_ids:
                    continue
                if resolved_filters:
                    func_types = self._extract_types_from_record(f)
                    if not func_types & resolved_filters:
                        continue
                filtered.append(f)
            return filtered
        finally:
            session.close()

    def _resolve_vuln_type_filters(self, vuln_types: Optional[List[str]]) -> Optional[set]:
        if not vuln_types:
            return None
        raw_items = [str(x).strip() for x in vuln_types if str(x).strip()]
        if not raw_items:
            return None
        key_to_category = {}
        token_to_category = {}
        try:
            from src.ft_data_processing.scrawld_processor import VULN_SPECS, TOKEN_TO_SPEC
            key_to_category = {spec.key.upper(): spec.category for spec in VULN_SPECS}
            token_to_category = {tok: TOKEN_TO_SPEC[tok].category for tok in TOKEN_TO_SPEC.keys()}
        except Exception:
            key_to_category = {}
            token_to_category = {}
        resolved: set = set()
        for item in raw_items:
            upper = item.upper()
            if upper in key_to_category:
                resolved.add(self._norm_type(key_to_category[upper]))
                continue
            if item in token_to_category:
                resolved.add(self._norm_type(token_to_category[item]))
                continue
            if upper in token_to_category:
                resolved.add(self._norm_type(token_to_category[upper]))
                continue
            lower = item.lower()
            if lower in token_to_category:
                resolved.add(self._norm_type(token_to_category[lower]))
                continue
            resolved.add(self._norm_type(item))
        return resolved or None

    def _norm_type(self, s: str) -> str:
        return str(s).strip().lower().replace('-', '_').replace(' ', '_')

    def _extract_types_from_record(self, func) -> set:
        types: List[str] = []
        audit = getattr(func, 'llm_audit', None) or {}
        vt = audit.get('vulnerability_types') or audit.get('vulnerability_type')
        if isinstance(vt, list):
            types.extend([str(x) for x in vt if str(x).strip()])
        elif isinstance(vt, str) and vt.strip():
            types.append(vt.strip())
        col = getattr(func, 'vulnerability_types', None)
        if isinstance(col, list):
            types.extend([str(x) for x in col if str(x).strip()])
        elif isinstance(col, str) and col.strip():
            types.append(col.strip())
        label = getattr(func, 'label', None) or {}
        lvt = label.get('vulnerability_types') or label.get('vulnerability_type')
        if isinstance(lvt, list):
            types.extend([str(x) for x in lvt if str(x).strip()])
        elif isinstance(lvt, str) and lvt.strip():
            types.append(lvt.strip())
        details = label.get('vulnerability_details')
        if isinstance(details, list):
            for d in details:
                if not isinstance(d, dict):
                    continue
                t = d.get('category') or d.get('type')
                if isinstance(t, str) and t.strip():
                    types.append(t.strip())
        return {self._norm_type(t) for t in types if str(t).strip()}

    def _prepare_function_data(self, functions: List) -> List[Dict]:
        functions_data = []
        for func in functions:
            func_data = {'dataset_name': getattr(func, 'dataset_name', None), 'dataset_type': getattr(func, 'dataset_type', None), 'contract_name': getattr(func, 'contract_name', None), 'function_name': func.function_name, 'function_code': func.function_code, 'function_signature': func.function_signature, 'contract_context': func.contract_context or {}, 'called_functions': func.called_functions or [], 'caller_functions': func.caller_functions or [], 'slither_result': func.slither_result or {}, 'start_line': func.start_line, 'end_line': func.end_line, 'contract_path': func.contract_path, 'label': func.label, 'llm_audit': func.llm_audit or {}, 'solidity_version': func.solidity_version or '0.8.0'}
            func_data['_db_id'] = func.id
            func_data['_sample_id'] = func.sample_id
            functions_data.append(func_data)
        return functions_data

    def _save_fixes(self, functions_data: List[Dict]):
        for func_data in functions_data:
            function_id = func_data.get('_db_id')
            sample_id = func_data.get('_sample_id')
            if not function_id:
                continue
            llm_fix = func_data.get('llm_fix')
            if not llm_fix:
                continue
            verification = llm_fix.get('verification', {})
            metadata = llm_fix.get('metadata', {})
            tools_passed = verification.get('tools_passed')
            if not isinstance(tools_passed, bool):
                tools_passed = verification.get('slither_passed', False)
            fix_data = {'function_id': function_id, 'sample_id': sample_id, 'original_code': llm_fix.get('original_code'), 'fixed_code': llm_fix.get('fixed_code'), 'fix_explanation': llm_fix.get('fix_explanation') or llm_fix.get('fix_analysis'), 'vulnerabilities_fixed': llm_fix.get('vulnerabilities_fixed', []), 'original_severity': metadata.get('original_severity'), 'compiles': verification.get('compiles', False), 'slither_passed': bool(tools_passed), 'remaining_issues': verification.get('remaining_issues', []), 'verification_details': verification, 'model_name': metadata.get('model'), 'fix_attempts': metadata.get('attempts', 1), 'raw_fix_data': llm_fix}
            self.db_manager.save_fix(fix_data)

    def _safe_filename_component(self, value: Any, fallback: str='unknown') -> str:
        s = str(value) if value is not None else ''
        s = s.strip()
        if not s:
            return fallback
        s = re.sub('[^a-zA-Z0-9_\\-\\.]+', '_', s)
        return s[:180]

    def _extract_primary_vuln_type(self, func_data: Dict) -> str:
        audit = func_data.get('llm_audit') or {}
        vuln_types = audit.get('vulnerability_types')
        if isinstance(vuln_types, list) and vuln_types:
            return str(vuln_types[0])
        if isinstance(vuln_types, str) and vuln_types.strip():
            return vuln_types.strip()
        single = audit.get('vulnerability_type')
        if isinstance(single, str) and single.strip():
            return single.strip()
        llm_fix = func_data.get('llm_fix') or {}
        fixed = llm_fix.get('vulnerabilities_fixed')
        if isinstance(fixed, list) and fixed:
            return str(fixed[0])
        if isinstance(fixed, str) and fixed.strip():
            return fixed.strip()
        return 'unknown'

    def _choose_unique_path(self, path: Path) -> Path:
        if not path.exists():
            return path
        stem = path.stem
        suffix = path.suffix
        parent = path.parent
        for i in range(1, 10000):
            candidate = parent / f'{stem}_{i}{suffix}'
            if not candidate.exists():
                return candidate
        return parent / f'{stem}_{int(time.time())}{suffix}'

    def _should_output_json(self, func_data: Dict) -> bool:
        mode = (self.output_json_mode or 'failed').strip().lower()
        status = (func_data.get('_fix_status') or '').strip().lower()
        if mode == 'all':
            return True
        if mode == 'success':
            return status == 'success'
        return status.startswith('failed')

    def _save_fix_json(self, func_data: Dict):
        vuln_type = self._safe_filename_component(self._extract_primary_vuln_type(func_data))
        item_id = func_data.get('_sample_id') or func_data.get('_db_id') or 'unknown'
        item_id = self._safe_filename_component(item_id)
        status = (func_data.get('_fix_status') or 'unknown').strip().upper()
        if status == 'FAILED_VERIFICATION':
            prefix = 'FAIL_VERIFY'
        elif status == 'FAILED_LLM':
            prefix = 'FAIL_LLM'
        elif status == 'SUCCESS':
            prefix = 'OK'
        else:
            prefix = status or 'ITEM'
        filename = f'{prefix}_{vuln_type}_{item_id}.json'
        out_path = self.output_json_dir / filename
        if self.skip_existing_json and out_path.exists():
            return
        if not self.skip_existing_json:
            out_path = self._choose_unique_path(out_path)
        with open(out_path, 'w', encoding='utf-8') as f:
            payload = self._build_output_json_payload(func_data)
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def _build_output_json_payload(self, func_data: Dict) -> Dict:
        if self.output_json_full:
            return func_data
        contract_ctx = func_data.get('contract_context') or {}
        llm_audit = func_data.get('llm_audit') or {}
        llm_fix = func_data.get('llm_fix') or {}
        metadata = llm_fix.get('metadata') or {}
        audit_desc = llm_audit.get('description') or llm_audit.get('reasoning') or llm_audit.get('analysis')
        return {'ids': {'function_db_id': func_data.get('_db_id'), 'sample_id': func_data.get('_sample_id')}, 'result': {'status': func_data.get('_fix_status'), 'failure_reason': func_data.get('_fix_failure_reason')}, 'source': {'dataset_name': func_data.get('dataset_name'), 'dataset_type': func_data.get('dataset_type'), 'contract_path': func_data.get('contract_path'), 'contract_name': func_data.get('contract_name') or contract_ctx.get('contract_name'), 'function_name': func_data.get('function_name'), 'function_signature': func_data.get('function_signature'), 'start_line': func_data.get('start_line'), 'end_line': func_data.get('end_line'), 'solidity_version': func_data.get('solidity_version')}, 'audit': {'label': llm_audit.get('label'), 'severity': llm_audit.get('severity'), 'vulnerability_types': llm_audit.get('vulnerability_types') or llm_audit.get('vulnerability_type'), 'description': audit_desc}, 'fix': {'model': metadata.get('model'), 'timestamp': metadata.get('timestamp'), 'attempts': metadata.get('attempts'), 'vulnerabilities_fixed': llm_fix.get('vulnerabilities_fixed', []), 'original_function_code': func_data.get('function_code'), 'fixed_code': llm_fix.get('fixed_code'), 'fix_explanation': llm_fix.get('fix_explanation') or llm_fix.get('fix_analysis'), 'verification': llm_fix.get('verification', {})}}

    def _augment_verification_with_tools(self, func_data: Dict, fix_result: Dict) -> None:
        verification = fix_result.get('verification') or {}
        slither_passed = bool(verification.get('slither_passed', True))
        slither_issues = verification.get('remaining_issues', [])
        slither_tool = {'passed': slither_passed, 'issues': slither_issues}
        tool_results: Dict[str, Any] = dict(verification.get('tool_results') or {})
        tool_results['slither'] = slither_tool
        mythril_tool = None
        if self.enable_mythril_check:
            if isinstance(tool_results.get('mythril'), dict):
                mythril_tool = tool_results.get('mythril')
            elif 'mythril_passed' in verification or 'mythril_issues' in verification or 'mythril_error' in verification:
                mythril_tool = {'passed': bool(verification.get('mythril_passed', True)), 'issues': verification.get('mythril_issues', []), 'error': verification.get('mythril_error')}
                tool_results['mythril'] = mythril_tool
            else:
                full_contract = verification.get('full_contract')
                if isinstance(full_contract, str) and full_contract.strip():
                    res = self.mythril_manager.analyze_source(contract_src=full_contract, timeout=int(self.mythril_timeout), severities=self.mythril_severities if self.mythril_severities is not None else ('high', 'medium'), max_issues=50)
                    mythril_tool = {'passed': bool(res.passed), 'issue_count': int(res.issue_count), 'issues': res.issues, 'error': res.error, 'raw_json': res.raw_json}
                    tool_results['mythril'] = mythril_tool
                else:
                    mythril_tool = {'passed': True, 'skipped': True, 'error': 'no_full_contract'}
                    tool_results['mythril'] = mythril_tool
        tools_passed = True
        for v in tool_results.values():
            if isinstance(v, dict) and v.get('passed') is False:
                tools_passed = False
                break
        structured_remaining: List[Dict[str, Any]] = []
        for (name, v) in tool_results.items():
            if isinstance(v, dict) and v.get('passed') is False:
                structured_remaining.append({name: v})
        verification['tool_results'] = tool_results
        verification['tools_passed'] = bool(tools_passed)
        verification['remaining_issues'] = structured_remaining
        fix_result['verification'] = verification

    def _save_failure_log(self, func_data: Dict, fix_result: Optional[Dict], reason: str):
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
            func_name = func_data.get('function_name', 'unknown')
            safe_contract = ''.join([c for c in contract_name if c.isalnum() or c in ('_', '-')])
            safe_func = ''.join([c for c in func_name if c.isalnum() or c in ('_', '-')])
            filename = f'FAIL_{timestamp}_{safe_contract}_{safe_func}.md'
            filepath = self.failure_log_dir / filename
            content = []
            content.append(f'# Fix Failure Report: {contract_name}.{func_name}')
            content.append(f"\n**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            content.append(f'**Reason:** {reason}')
            content.append(f"**Contract File:** {func_data.get('contract_path')}")
            content.append(f"**Start Line:** {func_data.get('start_line')}")
            llm_audit = func_data.get('llm_audit', {})
            description = llm_audit.get('description') or llm_audit.get('reasoning') or llm_audit.get('analysis')
            content.append(f'\n## Vulnerability Info')
            content.append(f"- **Label:** {llm_audit.get('label')}")
            content.append(f"- **Severity:** {llm_audit.get('severity')}")
            content.append(f'- **Description:**\n{description}')
            if fix_result:
                verification = fix_result.get('verification', {})
                content.append(f'\n## Verification Details')
                content.append(f"- **Compiles:** {verification.get('compiles')}")
                content.append(f"- **Slither Passed:** {verification.get('slither_passed')}")
                if verification.get('error'):
                    content.append(f'\n### Compilation/Runtime Errors')
                    content.append(f"```text\n{verification.get('error')}\n```")
                if verification.get('slither_output'):
                    content.append(f'\n### Slither Output')
                    content.append(f"```text\n{verification.get('slither_output')}\n```")
                if verification.get('remaining_issues'):
                    content.append(f'\n### Remaining Issues')
                    for issue in verification.get('remaining_issues', []):
                        content.append(f'- {issue}')
            content.append(f'\n## Original Code')
            content.append(f"```solidity\n{func_data.get('function_code')}\n```")
            if fix_result and fix_result.get('fixed_code'):
                content.append(f'\n## Generated Fix')
                content.append(f"```solidity\n{fix_result.get('fixed_code')}\n```")
                content.append(f'\n## Fix Explanation')
                content.append(f"{fix_result.get('fix_explanation') or fix_result.get('fix_analysis')}")
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
        except Exception as e:
            print(f'Error saving failure log: {e}')

def main():
    parser = argparse.ArgumentParser(description='LLM修复流水线 - 阶段2')
    parser.add_argument('--db-path', type=str, default='sqlite:///smart_contracts.db', help='数据库路径')
    parser.add_argument('--dataset-types', type=str, nargs='+', choices=['wild', 'curated'], help='数据集类型 (可多选)')
    parser.add_argument('--dataset-names', type=str, nargs='+', help='数据集名称 (可多选)')
    parser.add_argument('--limit', type=int, help='最大处理数量')
    parser.add_argument('--include-safe', action='store_true', help='包含标记为安全的函数')
    parser.add_argument('--refix', action='store_true', help='重新修复已有修复结果的数据')
    parser.add_argument('--skip-fixed-scope', type=str, choices=['model', 'any'], default='model', help='跳过已修复数据的范围：model=仅当前--model修复过才跳过（推荐，避免同模型重复）；any=任意模型修复过就跳过（旧行为）')
    parser.add_argument('--min-severity', type=float, default=0.0, help='最小严重程度阈值 (0-10)')
    parser.add_argument('--api-key', type=str, default=None, help='OpenAI API Key (默认从环境变量OPENAI_API_KEY读取)')
    parser.add_argument('--base-url', type=str, default='https://api.deepseek.com', help='API Base URL (支持OpenAI兼容接口)')
    parser.add_argument('--model', type=str, default='deepseek-chat', help='模型名称')
    parser.add_argument('--temperature', type=float, default=0.4, help='生成温度')
    parser.add_argument('--disable-compilation-check', action='store_true', help='禁用编译检查')
    parser.add_argument('--disable-slither-check', action='store_true', help='禁用Slither检查')
    parser.add_argument('--solc-version', type=str, default='0.8.0', help='Solidity编译器版本')
    parser.add_argument('--max-fix-attempts', type=int, default=3, help='每个函数最大修复尝试次数')
    parser.add_argument('--save-interval', type=int, default=10, help='每处理多少条数据保存一次')
    parser.add_argument('--concurrency', type=int, default=5, help='并发请求数量')
    parser.add_argument('--log-failures', action='store_true', help='将失败的修复记录到本地文件')
    parser.add_argument('--failure-log-dir', type=str, default='failure_logs', help='失败日志保存目录')
    parser.add_argument('--output-json', action='store_true', help='将修复结果输出为单独的json文件（默认只输出失败，可用 --output-json-mode 调整）')
    parser.add_argument('--output-json-dir', type=str, default='fix_json_outputs', help='json文件输出目录（配合--output-json使用）')
    parser.add_argument('--output-json-mode', type=str, choices=['failed', 'all', 'success'], default='failed', help='json输出模式：failed=仅失败（默认）；all=全部；success=仅成功')
    parser.add_argument('--no-skip-existing-json', action='store_true', help='不跳过已存在的单条json输出；若文件已存在将自动追加后缀保存（默认会跳过以避免重复）')
    parser.add_argument('--output-json-full', action='store_true', help='--output-json 输出全量func_data（包含上下文/切片等大字段）；默认输出精简的“修复相关”字段')
    parser.add_argument('--enable-mythril-check', action='store_true', help='启用Mythril检查（基于verification.full_contract）。默认关闭以避免环境缺少mythril导致额外开销')
    parser.add_argument('--mythril-timeout', type=int, default=10, help='Mythril超时时间（秒）')
    parser.add_argument('--mythril-severities', type=str, nargs='*', default=None, help='Mythril严重性过滤（默认: high medium），例如: --mythril-severities high medium')
    parser.add_argument('--mythril-bin', type=str, default='myth', help='Mythril可执行文件名/路径（默认: myth）')
    parser.add_argument('--verbose', action='store_true', help='输出详细信息（包括LLM的完整响应）')
    parser.add_argument('--use-label-annotation', action='store_true', help='当 llm_audit 缺失时，使用数据库中的 ground-truth label + slither_result 构造伪 annotation 进行修复（默认关闭，不影响原逻辑）')
    parser.add_argument('--use-rich-fix-prompt', action='store_true', help='启用 richer 修复 prompt（包含漏洞类型、漏洞行片段、Slither 报告等）。默认关闭，不影响原 prompt。')
    parser.add_argument('--vuln-types', type=str, nargs='*', default=None, help='可选：仅选择指定漏洞类型进行修复/数据生成。支持 ScrawlD 映射中的 category（如 reentrancy）、key（如 REENTRANCY）、token（如 RENT）。不传则不筛选（默认行为不变）。')
    args = parser.parse_args()
    api_key = args.api_key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        print('错误: 请提供API Key (通过--api-key参数或OPENAI_API_KEY环境变量)')
        sys.exit(1)
    print('初始化组件...')
    db_manager = DBManager(db_path=args.db_path)
    config = FixerConfig(api_key=api_key, base_url=args.base_url, model=args.model, temperature=args.temperature, verbose=args.verbose, enable_compilation_check=not args.disable_compilation_check, enable_slither_check=not args.disable_slither_check, solc_version=args.solc_version, max_fix_attempts=args.max_fix_attempts, enable_mythril_check=args.enable_mythril_check, mythril_timeout=args.mythril_timeout, mythril_severities=args.mythril_severities, mythril_bin=args.mythril_bin, use_rich_fix_prompt=getattr(args, 'use_rich_fix_prompt', False))
    fixer = LLMFixer(config)
    pipeline = FixingPipeline(db_manager=db_manager, fixer=fixer, save_interval=args.save_interval, concurrency=args.concurrency, log_failures=args.log_failures, failure_log_dir=args.failure_log_dir, output_json=args.output_json, output_json_dir=args.output_json_dir, skip_existing_json=not args.no_skip_existing_json, output_json_mode=args.output_json_mode, output_json_full=args.output_json_full, use_label_annotation=getattr(args, 'use_label_annotation', False), enable_mythril_check=args.enable_mythril_check, mythril_timeout=args.mythril_timeout, mythril_severities=args.mythril_severities, mythril_bin=args.mythril_bin)
    try:
        pipeline.run(dataset_types=args.dataset_types, dataset_names=args.dataset_names, limit=args.limit, only_vulnerable=not args.include_safe, skip_already_fixed=not args.refix, skip_fixed_scope=args.skip_fixed_scope, min_severity=args.min_severity, vuln_types=getattr(args, 'vuln_types', None))
    except KeyboardInterrupt:
        print('\n\n用户中断，正在保存已处理的数据...')
        print('已保存！')
    except Exception as e:
        print(f'\n发生错误: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)
if __name__ == '__main__':
    main()
