import sys
import json
from pathlib import Path
from dataclasses import asdict, is_dataclass
from typing import Dict, List, Tuple, Union
from src.ft_data_processing.smartbugs_processor import SmartBugsProcessor
from src.ft_data_processing.scrawld_processor import ScrawlDProcessor
from src.ft_data_processing.function_level_processor import FunctionLevelProcessor, FunctionContext
from src.database.db_manager import DBManager
from src.common.paths import RAW_DIR, PROCESSED_DIR
from src.tools.prompt_formatter import PromptFormatter

class ContractDatasetPipeline:

    def __init__(self, config: Dict):
        self.config = self._normalize_config(config)
        self.output_dir = Path(self.config['output_dir'])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.prompt_formatter = PromptFormatter()

    def _normalize_config(self, config: Dict) -> Dict:
        if 'datasets' in config:
            return config
        print('  ℹ️  检测到旧版配置，自动转换为新版格式...')
        datasets = []
        if 'smartbugs_wild_dir' in config:
            datasets.append({'name': 'smartbugs_wild', 'path': config['smartbugs_wild_dir'], 'type': 'wild', 'sample_limit': config.get('wild_sample_limit', None), 'quality_filter': True})
        if 'smartbugs_curated_dir' in config:
            datasets.append({'name': 'smartbugs_curated', 'path': config['smartbugs_curated_dir'], 'type': 'curated', 'sample_limit': config.get('curated_sample_limit', None), 'quality_filter': False})
        config['datasets'] = datasets
        return config

    def run_full_pipeline(self):
        print('\n' + '=' * 70)
        print('通用智能合约数据集处理 Pipeline')
        print('=' * 70)
        print(f'\n📁 数据集配置:')
        for (i, dataset) in enumerate(self.config['datasets'], 1):
            limit_str = f"前{dataset.get('sample_limit')}个" if dataset.get('sample_limit') else '全部'
            print(f"  {i}. {dataset['name']}")
            print(f"     路径: {dataset['path']}")
            print(f"     类型: {dataset['type']}")
            print(f'     数量: {limit_str}')
        print('\n【阶段1】合约级处理...')
        all_contracts = self.contract_processing()
        print('\n【阶段2】函数级处理+标注（带早期去重和过滤）...')
        batch_size = self.config.get('batch_size', 100)
        save_to_db = self.config.get('save_to_db', False)
        function_dataset = self.function_processing(all_contracts, batch_size=batch_size, save_to_db=save_to_db)
        print('\n' + '=' * 70)
        print('✅ Pipeline 执行完成！')
        print('=' * 70)
        self.print_summary()

    def contract_processing(self) -> List:
        output_dir = self.output_dir / 'stage1_contract_level'
        output_dir.mkdir(parents=True, exist_ok=True)
        all_contracts = []
        dataset_stats = []
        for dataset_config in self.config['datasets']:
            print(f"\n  处理数据集: {dataset_config['name']}")
            print(f"    路径: {dataset_config['path']}")
            print(f"    类型: {dataset_config['type']}")
            contracts = []
            sample_limit = dataset_config.get('sample_limit')
            if sample_limit:
                print(f'    采样数量: {sample_limit}')
            else:
                print(f'    处理全部合约')
            if dataset_config['type'] == 'wild':
                from src.ft_data_processing.smartbugs_processor import SmartBugsProcessor
                processor = SmartBugsProcessor(wild_dir=dataset_config['path'], curated_dir=None, solidifi_dir=None, output_dir=str(output_dir))
                contracts = processor.process_wild(sample_size=sample_limit)
                if dataset_config.get('quality_filter', True):
                    original_count = len(contracts)
                    contracts = processor.filter_wild_by_quality(contracts)
                    print(f'    质量过滤: {original_count} → {len(contracts)}')
            elif dataset_config['type'] == 'curated':
                from src.ft_data_processing.smartbugs_processor import SmartBugsProcessor
                processor = SmartBugsProcessor(wild_dir=None, curated_dir=dataset_config['path'], solidifi_dir=None, output_dir=str(output_dir))
                contracts = processor.process_curated(sample_size=sample_limit)
            elif dataset_config['type'] == 'solidifi':
                from src.ft_data_processing.smartbugs_processor import SmartBugsProcessor
                processor = SmartBugsProcessor(wild_dir=None, curated_dir=None, solidifi_dir=dataset_config['path'], output_dir=str(output_dir))
                contracts = processor.process_solidifi(sample_size=sample_limit)
            elif dataset_config['type'] == 'scrawld':
                thresholds = dataset_config.get('thresholds')
                processor = ScrawlDProcessor(scrawld_dir=dataset_config['path'], output_dir=str(output_dir), thresholds=thresholds)
                contracts = processor.process_scrawld(sample_size=sample_limit)
            for contract in contracts:
                contract.metadata['dataset'] = dataset_config['name']
                contract.metadata['dataset_type'] = dataset_config['type']
            save_filename = f"{dataset_config['name']}_processed.json"
            processor.save_contracts(contracts, save_filename)
            print(f'    ✓ 保存: {len(contracts)} 个合约 → {save_filename}')
            all_contracts.extend(contracts)
            dataset_stats.append({'name': dataset_config['name'], 'type': dataset_config['type'], 'count': len(contracts)})
        print(f'\n  【阶段1总结】')
        for stat in dataset_stats:
            print(f"    {stat['name']}: {stat['count']} 个合约")
        print(f'    总计: {len(all_contracts)} 个合约')
        with open(output_dir / 'dataset_summary.json', 'w') as f:
            json.dump(dataset_stats, f, indent=2)
        return all_contracts

    def function_processing(self, all_contracts: List, batch_size: int=100, save_to_db: bool=False):
        processor = FunctionLevelProcessor(use_slither=self.config.get('use_slither', False), debug=self.config.get('debug', False), enable_deduplication=self.config.get('enable_deduplication', True), enable_filtering=self.config.get('enable_filtering', True))
        output_dir = self.output_dir / 'stage2_function_level'
        output_dir.mkdir(parents=True, exist_ok=True)
        from collections import defaultdict
        contracts_by_dataset = defaultdict(list)
        for contract in all_contracts:
            dataset_name = contract.metadata.get('dataset', 'unknown')
            contracts_by_dataset[dataset_name].append(contract)
        print(f'\n  处理 {len(all_contracts)} 个合约 (批大小: {batch_size})...')
        for (dataset_name, contracts) in contracts_by_dataset.items():
            print(f'    - {dataset_name}: {len(contracts)} 个合约')
        total_processed = 0
        total_failed = 0
        num_batches = (len(all_contracts) + batch_size - 1) // batch_size
        collected_functions: List[FunctionContext] = []

        def _is_vuln_func(f: FunctionContext) -> bool:
            lbl = getattr(f, 'label', None) or {}
            if isinstance(lbl, dict) and 'is_vulnerable' in lbl:
                return bool(lbl.get('is_vulnerable'))
            sr = getattr(f, 'slither_result', None) or {}
            if isinstance(sr, dict) and 'is_vulnerable' in sr:
                return bool(sr.get('is_vulnerable'))
            return False
        print(f'  总共 {num_batches} 批')
        for batch_idx in range(num_batches):
            start_idx = batch_idx * batch_size
            end_idx = min((batch_idx + 1) * batch_size, len(all_contracts))
            batch_contracts = all_contracts[start_idx:end_idx]
            print(f'\n  【批次 {batch_idx + 1}/{num_batches}】处理合约 {start_idx + 1}-{end_idx}/{len(all_contracts)}')
            if processor.enable_deduplication:
                hashes_before = set(processor._dedup_table.keys())
            else:
                hashes_before = set()
            batch_processed = 0
            batch_failed = 0
            for (i, contract) in enumerate(batch_contracts):
                dataset_name = contract.metadata.get('dataset', 'unknown')
                dataset_type = contract.metadata.get('dataset_type', 'unknown')
                try:
                    contract_info = {'dataset': dataset_name, 'dataset_type': dataset_type, 'solidity_version': contract.solidity_version, 'contract_name': contract.contract_name, 'label': contract.label, 'functions': contract.functions}
                    returned_functions = processor.process_contract_to_functions(contract_file=contract.file_path, contract_info=contract_info)
                    if not processor.enable_deduplication and returned_functions:
                        collected_functions.extend(returned_functions)
                    batch_processed += 1
                    total_processed += 1
                except Exception as e:
                    batch_failed += 1
                    total_failed += 1
                    if self.config.get('debug'):
                        print(f'    错误: {contract.file_path}: {e}')
            if processor.enable_deduplication:
                hashes_after = set(processor._dedup_table.keys())
                new_hashes = hashes_after - hashes_before
                batch_new_functions = len(new_hashes)
                print(f'    批次处理: 成功{batch_processed}, 失败{batch_failed}, 新增函数{batch_new_functions}')
                new_functions = [processor._dedup_table[h][0] for h in new_hashes]
            else:
                new_functions = []
                print(f'    批次处理: 成功{batch_processed}, 失败{batch_failed}')
            if save_to_db and new_functions:
                to_save = new_functions
                if self.config.get('keep_only_vulnerable', False):
                    before = len(to_save)
                    to_save = [f for f in to_save if _is_vuln_func(f)]
                    print(f'    【数据库保存】仅保留有漏洞函数: {before} → {len(to_save)}')
                print(f'    【数据库保存】新增 {len(to_save)} 个函数...')
                if to_save:
                    self.save_to_database(to_save, mode='append')
        print(f'\n  所有批次处理完成: 成功{total_processed}, 失败{total_failed}')
        if processor.enable_deduplication:
            all_functions = processor.get_final_functions()
            processor._stats['final_count'] = len(all_functions)
        else:
            all_functions = collected_functions
            processor._stats['final_count'] = len(all_functions)
        if self.config.get('keep_only_vulnerable', False):
            before = len(all_functions)
            all_functions = [f for f in all_functions if _is_vuln_func(f)]
            processor._stats['final_count'] = len(all_functions)
            print(f'  仅保留有漏洞函数: {before} → {len(all_functions)}')
        processor.print_stats()
        print(f'  ✓ 最终保留: {len(all_functions)} 个函数')
        processor.save_function_contexts(all_functions, str(output_dir / 'all_functions.json'))
        return all_functions

    def save_to_database(self, function_dataset: List[FunctionContext], mode: str='append'):
        db_path = self.config.get('db_path', 'sqlite:///smart_contracts.db')
        try:
            dataset_to_save = [asdict(item) if is_dataclass(item) else item for item in function_dataset]
            db_manager = DBManager(db_path)
            db_manager.save_functions(dataset_to_save)
            stats = db_manager.get_stats()
            print(f'    数据库更新完成:')
            print(f"      总函数数量: {stats['total_functions']}")
            print(f"      有漏洞函数: {stats['vulnerable_functions']} ({stats['vulnerability_ratio']:.1%})")
            if self.config.get('debug'):
                print('      数据集分布:')
                for (name, count) in stats['datasets'].items():
                    print(f'        - {name}: {count}')
        except Exception as e:
            print(f'    ⚠️ 保存到数据库失败: {e}')
            if self.config.get('debug'):
                import traceback
                traceback.print_exc()

    def _get_field(self, item, field: str, default=None):
        if isinstance(item, dict):
            return item.get(field, default)
        if hasattr(item, field):
            return getattr(item, field)
        return default

    def create_splits(self, function_dataset):
        import random
        output_dir = self.output_dir / 'stage3_splits'
        output_dir.mkdir(parents=True, exist_ok=True)

        def get_dataset_type(f):
            metadata = self._get_field(f, 'metadata', {})
            return metadata.get('dataset_type') if isinstance(metadata, dict) else getattr(metadata, 'dataset_type', None)

        def is_vulnerable(f):
            label = self._get_field(f, 'label', {})
            if isinstance(label, dict):
                return label.get('is_vulnerable')
            return getattr(label, 'is_vulnerable', False)
        curated_funcs = [f for f in function_dataset if get_dataset_type(f) == 'curated']
        wild_funcs = [f for f in function_dataset if get_dataset_type(f) == 'wild']
        solidifi_funcs = [f for f in function_dataset if get_dataset_type(f) == 'solidifi']
        print(f'  Curated: {len(curated_funcs)} 个函数')
        print(f'  Wild: {len(wild_funcs)} 个函数')
        print(f'  SolidiFI: {len(solidifi_funcs)} 个函数')
        vulnerable_funcs = [f for f in function_dataset if is_vulnerable(f)]
        safe_funcs = [f for f in function_dataset if not is_vulnerable(f)]
        print(f'  有漏洞: {len(vulnerable_funcs)} 个函数')
        print(f'  安全: {len(safe_funcs)} 个函数')
        train_ratio = self.config.get('train_ratio', 0.7)
        val_ratio = self.config.get('val_ratio', 0.15)
        test_ratio = self.config.get('test_ratio', 0.15)
        random_seed = self.config.get('random_seed', 42)
        random.seed(random_seed)
        print(f'\n  【划分策略】分层随机划分')
        print(f'    比例: Train={train_ratio:.0%}, Val={val_ratio:.0%}, Test={test_ratio:.0%}')
        print(f'    随机种子: {random_seed}')
        train_funcs = []
        val_funcs = []
        test_funcs = []
        test_funcs.extend(curated_funcs)
        print(f'    Curated → Test: {len(curated_funcs)} 个')
        wild_vulnerable = [f for f in wild_funcs if is_vulnerable(f)]
        wild_safe = [f for f in wild_funcs if not is_vulnerable(f)]
        print(f'\n  【Wild数据分层】')
        print(f'    有漏洞: {len(wild_vulnerable)} 个')
        print(f'    安全: {len(wild_safe)} 个')
        for (funcs, label) in [(wild_vulnerable, '有漏洞'), (wild_safe, '安全')]:
            if len(funcs) == 0:
                continue
            random.shuffle(funcs)
            n = len(funcs)
            train_end = int(n * train_ratio)
            val_end = train_end + int(n * val_ratio)
            train_funcs.extend(funcs[:train_end])
            val_funcs.extend(funcs[train_end:val_end])
            test_funcs.extend(funcs[val_end:])
            print(f'    {label}: Train={len(funcs[:train_end])}, Val={len(funcs[train_end:val_end])}, Test={len(funcs[val_end:])}')
        solidifi_vulnerable = [f for f in solidifi_funcs if is_vulnerable(f)]
        solidifi_safe = [f for f in solidifi_funcs if not is_vulnerable(f)]
        print(f'\n  【SolidiFI数据分层】')
        print(f'    有漏洞: {len(solidifi_vulnerable)} 个')
        print(f'    安全: {len(solidifi_safe)} 个')
        for (funcs, label) in [(solidifi_vulnerable, '有漏洞'), (solidifi_safe, '安全')]:
            if len(funcs) == 0:
                continue
            random.shuffle(funcs)
            n = len(funcs)
            train_end = int(n * train_ratio)
            val_end = train_end + int(n * val_ratio)
            train_funcs.extend(funcs[:train_end])
            val_funcs.extend(funcs[train_end:val_end])
            test_funcs.extend(funcs[val_end:])
            print(f'    {label}: Train={len(funcs[:train_end])}, Val={len(funcs[train_end:val_end])}, Test={len(funcs[val_end:])}')
        random.shuffle(train_funcs)
        random.shuffle(val_funcs)
        random.shuffle(test_funcs)
        splits = {'train': [f if isinstance(f, dict) else vars(f) for f in train_funcs], 'val': [f if isinstance(f, dict) else vars(f) for f in val_funcs], 'test': [f if isinstance(f, dict) else vars(f) for f in test_funcs]}
        print(f'\n  【最终划分】')
        for (split_name, split_data) in splits.items():
            split_file = output_dir / f'{split_name}.json'
            with open(split_file, 'w') as f:
                json.dump(split_data, f, indent=2)

            def check_vulnerable(f):
                if f.get('llm_audit'):
                    return f['llm_audit'].get('is_vulnerable', False)
                if f.get('label'):
                    return f['label'].get('is_vulnerable', False)
                slither = f.get('slither_result', {})
                if isinstance(slither, dict):
                    return slither.get('is_vulnerable', False)
                return False
            vuln_count = sum((1 for f in split_data if check_vulnerable(f)))
            safe_count = len(split_data) - vuln_count
            print(f'    {split_name}: {len(split_data)} 个样本 (漏洞:{vuln_count}, 安全:{safe_count}) -> {split_file}')
        summary = {'train_size': len(train_funcs), 'val_size': len(val_funcs), 'test_size': len(test_funcs), 'total': len(function_dataset), 'curated_in_test': len(curated_funcs), 'vulnerable_total': len(vulnerable_funcs), 'safe_total': len(safe_funcs), 'split_strategy': 'stratified_random', 'train_ratio': train_ratio, 'val_ratio': val_ratio, 'test_ratio': test_ratio, 'random_seed': random_seed}
        with open(output_dir / 'splits_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        return splits

    def generate_final_dataset(self, function_dataset, splits):
        output_dir = self.output_dir / 'stage4_final'
        output_dir.mkdir(parents=True, exist_ok=True)
        for (split_name, split_data) in splits.items():
            training_samples = []
            for (idx, func_data) in enumerate(split_data):
                sample_id = self.generate_sample_id(func_data, split_name, idx)
                instruction = self.prompt_formatter.format_instruction()
                input_text = self.prompt_formatter.format_input(func_data)
                output_text = self.prompt_formatter.format_output(func_data)
                training_samples.append({'id': sample_id, 'instruction': instruction, 'input': input_text, 'output': output_text})
            output_file = output_dir / f'{split_name}_formatted.jsonl'
            with open(output_file, 'w') as f:
                for sample in training_samples:
                    f.write(json.dumps(sample, ensure_ascii=False) + '\n')
            print(f'  {split_name}: {len(training_samples)} 样本 -> {output_file}')

    def generate_sample_id(self, func_data: Dict, split_name: str, idx: int) -> str:
        dataset = func_data.get('metadata', {}).get('dataset', 'unknown')
        contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
        func_name = func_data.get('function_name', 'unknown')
        sample_id = f'{dataset}_{contract_name}_{func_name}_{split_name}_{idx}'
        sample_id = sample_id.replace('/', '_').replace('\\', '_').replace(' ', '_')
        return sample_id

    def print_summary(self):
        summary_file = self.output_dir / 'stage3_splits' / 'splits_summary.json'
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)
            print('\n' + '=' * 70)
            print('📊 处理摘要')
            print('=' * 70)
            print(f"数据集划分策略: {summary.get('split_strategy', 'unknown')}")
            print(f"随机种子: {summary.get('random_seed', 'N/A')}")
            print()
            print(f"训练集: {summary['train_size']} 个函数 ({summary['train_size'] / summary['total'] * 100:.1f}%)")
            print(f"验证集: {summary['val_size']} 个函数 ({summary['val_size'] / summary['total'] * 100:.1f}%)")
            print(f"测试集: {summary['test_size']} 个函数 ({summary['test_size'] / summary['total'] * 100:.1f}%)")
            print(f"  └─ 其中Curated: {summary.get('curated_in_test', 0)} 个")
            print()
            print(f"总计: {summary['total']} 个函数")
            print(f"  └─ 有漏洞: {summary.get('vulnerable_total', 0)} 个")
            print(f"  └─ 安全: {summary.get('safe_total', 0)} 个")
            print('=' * 70)

def main():
    config = {'output_dir': PROCESSED_DIR / 'scrawld_smoke_vulnonly', 'datasets': [{'name': 'scrawld', 'path': '/home/user/zn/ScrawlD', 'type': 'scrawld', 'sample_limit': 200, 'quality_filter': False}], 'use_slither': True, 'debug': False, 'enable_deduplication': True, 'enable_filtering': True, 'batch_size': 500, 'save_to_db': True, 'db_path': 'sqlite:///smart_contracts.db', 'keep_only_vulnerable': True, 'train_ratio': 0.7, 'val_ratio': 0.15, 'test_ratio': 0.15, 'random_seed': 42}
    pipeline = ContractDatasetPipeline(config)
    pipeline.run_full_pipeline()
SmartBugsPipeline = ContractDatasetPipeline
if __name__ == '__main__':
    main()
