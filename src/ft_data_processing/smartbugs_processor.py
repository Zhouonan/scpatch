\
\
\
   

import os
import json
import re
import csv
import subprocess
import bisect
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import pandas as pd
from tqdm import tqdm
from collections import defaultdict, Counter
import solcx
from solcx import compile_source, install_solc

@dataclass
class ContractInfo:
              
    file_path: str
    contract_name: str
    solidity_version: str
    functions: List[Dict]
    label: Optional[Dict] = None
    metadata: Optional[Dict] = None


class SmartBugsProcessor:
                          
    
                               
    VULNERABILITY_TYPES = {
        'access_control': 'Access Control',
        'arithmetic': 'Integer Overflow/Underflow',
        'bad_randomness': 'Bad Randomness',
        'denial_of_service': 'Denial of Service',
        'front_running': 'Front Running',
        'reentrancy': 'Reentrancy',
        'time_manipulation': 'Time Manipulation',
        'unchecked_low_level_calls': 'Unchecked Low Level Calls',
        'short_addresses': 'Short Addresses',
        'other': 'Other'
    }

                     
    SOLIDIFI_MAPPING = {
        'Re-entrancy': 'reentrancy',
        'Timestamp-Dependency': 'time_manipulation',
        'Unhandled-Exceptions': 'unchecked_low_level_calls',
        'Unchecked-Send': 'unchecked_low_level_calls',
        'TOD': 'front_running',
        'Overflow-Underflow': 'arithmetic',
        'tx.origin': 'access_control'
    }
    
    def __init__(self, 
                 wild_dir: str = None,
                 curated_dir: str = None, 
                 solidifi_dir: str = None,
                 output_dir: str = "./processed_data"):
\
\
\
\
\
\
\
\
           
        self.wild_dir = Path(wild_dir) if wild_dir is not None else None
        self.curated_dir = Path(curated_dir) if curated_dir is not None else None
        self.solidifi_dir = Path(solidifi_dir) if solidifi_dir is not None else None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
              
        self.stats = {
            'wild': {'total': 0, 'valid': 0, 'errors': []},
            'curated': {'total': 0, 'valid': 0, 'errors': []},
            'solidifi': {'total': 0, 'valid': 0, 'errors': []}
        }
    
    def process_both_datasets(self):
                         
        print("="*60)
        print("SmartBugs 数据集处理器")
        print("="*60)
        
                                  
        print("\n[阶段 1/5] 处理 SmartBugs Curated...")
        curated_data = self.process_curated()
        
                               
        print("\n[阶段 2/5] 处理 SmartBugs Wild...")
        wild_data = self.process_wild()
        
                      
        print("\n[阶段 3/5] 版本分析...")
        self.analyze_versions(wild_data, curated_data)
        
                      
        print("\n[阶段 4/5] 质量过滤...")
        filtered_wild = self.filter_wild_by_quality(wild_data)
        
                       
        print("\n[阶段 5/5] 创建数据集划分...")
        self.create_dataset_splits(filtered_wild, curated_data)
        
              
        self.generate_report()
        
        print("\n✅ 处理完成！")
        return filtered_wild, curated_data
    
    def process_curated(self, sample_size: Optional[int] = None) -> List[ContractInfo]:
\
\
\
\
\
\
           
        print("处理 SmartBugs Curated...")
        
        if self.curated_dir is None:
            print("  警告: curated_dir 未设置，跳过处理")
            return []
            
                
        vuln_map = {}
        vuln_json_path = self.curated_dir / 'vulnerabilities.json'
        if vuln_json_path.exists():
            try:
                with open(vuln_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                                 
                        path = item['path'].replace('\\', '/')
                        vuln_map[path] = item['vulnerabilities']
                print(f"  已加载 {len(vuln_map)} 个文件的漏洞标注")
            except Exception as e:
                print(f"  加载 vulnerabilities.json 失败: {e}")
        
        contracts = []
        
                                                                   
                                                  
        target_dir = self.curated_dir
        if (target_dir / 'dataset').exists() and (target_dir / 'dataset').is_dir():
            target_dir = target_dir / 'dataset'
            print(f"  检测到 dataset 子目录，切换路径到: {target_dir}")
            
                   
        all_files = []
        for vuln_dir in target_dir.iterdir():
            if not vuln_dir.is_dir():
                continue
            
            vuln_type = vuln_dir.name
            
                        
            if vuln_type.startswith('.') or vuln_type in ['dataset', 'scripts', 'tools']:
                continue
            
            for sol_file in vuln_dir.glob("*.sol"):
                all_files.append((sol_file, vuln_type))
        
        print(f"  找到总计 {len(all_files)} 个合约文件")
        
               
        if sample_size:
            import random
            original_count = len(all_files)
            sample_count = min(sample_size, len(all_files))
            all_files = random.sample(all_files, sample_count)
            print(f"  采样: {original_count} → {len(all_files)} 个合约")
            
                 
        for sol_file, vuln_type in tqdm(all_files, desc="  处理 Curated"):
            self.stats['curated']['total'] += 1
            
            try:
                        
                code = sol_file.read_text(encoding='utf-8', errors='ignore')
                
                                       
                line_offsets = [0]
                for i, char in enumerate(code):
                    if char == '\n':
                        line_offsets.append(i + 1)
                
                      
                version = self.extract_solidity_version(code)
                
                      
                functions = self.extract_functions(code)
                
                           
                try:
                    rel_path = sol_file.relative_to(self.curated_dir)
                    rel_path_str = str(rel_path).replace('\\', '/')
                except ValueError:
                    rel_path_str = ""
                
                file_vulns = vuln_map.get(rel_path_str, [])
                
                           
                for func in functions:
                    start_idx = func['start_pos']
                    end_idx = start_idx + len(func['code'])
                    
                                              
                                               
                    start_line = bisect.bisect_right(line_offsets, start_idx)
                    end_line = bisect.bisect_right(line_offsets, end_idx)
                    
                    func['lines'] = [start_line, end_line]
                    func['vulnerabilities'] = []
                    func['is_vulnerable'] = False
                    
                    if file_vulns:
                        for v in file_vulns:
                                            
                            matched_lines = []
                            for vuln_line in v['lines']:
                                if start_line <= vuln_line <= end_line:
                                    matched_lines.append(vuln_line)
                            
                            if matched_lines:
                                func['vulnerabilities'].append({
                                    'category': v['category'],
                                    'lines': matched_lines
                                })
                                func['is_vulnerable'] = True

                        
                contract = ContractInfo(
                    file_path=str(sol_file),
                    contract_name=sol_file.stem,
                    solidity_version=version,
                    functions=functions,
                    label={
                        'has_vulnerability': True,
                        'vulnerability_type': vuln_type,
                        'vulnerability_name': self.VULNERABILITY_TYPES.get(vuln_type, vuln_type),
                        'source': 'curated',
                        'detailed_vulns': file_vulns
                    },
                    metadata={
                        'dataset': 'smartbugs_curated',
                        'ground_truth': True
                    }
                )
                
                contracts.append(contract)
                self.stats['curated']['valid'] += 1
                
            except Exception as e:
                self.stats['curated']['errors'].append({
                    'file': str(sol_file),
                    'error': str(e)
                })
        
        print(f"  ✓ 成功处理: {self.stats['curated']['valid']}/{self.stats['curated']['total']}")
        
                 
        self.save_contracts(contracts, 'curated_processed.json')
        
        return contracts

    def process_solidifi(self, sample_size: Optional[int] = None) -> List[ContractInfo]:
\
\
\
           
        print("处理 SolidiFI Benchmark...")
        
        if self.solidifi_dir is None:
            print("  警告: solidifi_dir 未设置，跳过处理")
            return []
            
        contracts = []
        contracts_dir = self.solidifi_dir / 'buggy_contracts'
        
        if not contracts_dir.exists():
            print(f"  错误: 找不到目录 {contracts_dir}")
            return []
            
                  
        all_files = []
                                                          
        for bug_type_dir in contracts_dir.iterdir():
            if not bug_type_dir.is_dir():
                continue
                
                                         
            raw_bug_type = bug_type_dir.name
            
            for sol_file in bug_type_dir.glob("*.sol"):
                                              
                                             
                bug_log_name = sol_file.name.replace('buggy_', 'BugLog_').replace('.sol', '.csv')
                bug_log_file = bug_type_dir / bug_log_name
                
                if bug_log_file.exists():
                    all_files.append((sol_file, bug_log_file, raw_bug_type))

        print(f"  找到总计 {len(all_files)} 个带有 Log 的合约文件")
        
        if sample_size:
            import random
            original_count = len(all_files)
            sample_count = min(sample_size, len(all_files))
            all_files = random.sample(all_files, sample_count)
            print(f"  采样: {original_count} → {len(all_files)} 个合约")

        for sol_file, bug_log_file, raw_bug_type in tqdm(all_files, desc="  处理 SolidiFI"):
            self.stats['solidifi']['total'] += 1
            
            try:
                        
                code = sol_file.read_text(encoding='utf-8', errors='ignore')
                
                           
                injections = []
                with open(bug_log_file, 'r', encoding='utf-8') as f:
                                                                
                                                                    
                                  
                    lines = f.readlines()
                    if not lines: continue
                    
                                        
                    start_idx = 1 if 'loc' in lines[0] else 0
                    for line in lines[start_idx:]:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            try:
                                start_line = int(parts[0])
                                length = int(parts[1])
                                b_type = parts[2]
                                end_line = start_line + length - 1
                                injections.append({
                                    'start_line': start_line,
                                    'end_line': end_line,
                                    'bug_type': b_type
                                })
                            except ValueError:
                                continue
                
                         
                line_offsets = [0]
                for i, char in enumerate(code):
                    if char == '\n':
                        line_offsets.append(i + 1)
                
                      
                version = self.extract_solidity_version(code)
                
                      
                functions = self.extract_functions(code)
                
                standard_bug_type = self.SOLIDIFI_MAPPING.get(raw_bug_type, 'other')
                
                           
                contract_has_vuln = False
                for func in functions:
                    start_idx = func['start_pos']
                    end_idx = start_idx + len(func['code'])
                    
                                      
                    func_start_line = bisect.bisect_right(line_offsets, start_idx)
                    func_end_line = bisect.bisect_right(line_offsets, end_idx)
                    
                    func['lines'] = [func_start_line, func_end_line]
                    func['vulnerabilities'] = []
                    func['is_vulnerable'] = False
                    
                    for inj in injections:
                              
                        if not (inj['end_line'] < func_start_line or inj['start_line'] > func_end_line):
                                 
                            func['vulnerabilities'].append({
                                'category': standard_bug_type,
                                'lines': [max(func_start_line, inj['start_line']), min(func_end_line, inj['end_line'])]
                            })
                            func['is_vulnerable'] = True
                            contract_has_vuln = True
                
                        
                contract = ContractInfo(
                    file_path=str(sol_file),
                    contract_name=sol_file.stem,
                    solidity_version=version,
                    functions=functions,
                    label={
                        'has_vulnerability': contract_has_vuln,
                        'vulnerability_type': raw_bug_type,
                        'vulnerability_name': standard_bug_type,
                        'source': 'solidifi',
                        'injections': injections
                    },
                    metadata={
                        'dataset': 'solidifi',
                        'ground_truth': True
                    }
                )
                
                contracts.append(contract)
                self.stats['solidifi']['valid'] += 1
                
            except Exception as e:
                self.stats['solidifi']['errors'].append({
                    'file': str(sol_file),
                    'error': str(e)
                })
                
        print(f"  ✓ 成功处理: {self.stats['solidifi']['valid']}/{self.stats['solidifi']['total']}")
        
        self.save_contracts(contracts, 'solidifi_processed.json')
        return contracts
    
    def process_wild(self, sample_size: Optional[int] = None) -> List[ContractInfo]:
\
\
\
\
\
\
           
        print("处理 SmartBugs Wild (47K+合约)...")
        
        if self.wild_dir is None:
            print("  警告: wild_dir 未设置，跳过处理")
            return []
        
                                          
        contracts_dir = self.wild_dir / 'contracts'
        
        if not contracts_dir.exists():
                       
            contracts_dir = self.wild_dir
        
        sol_files = list(contracts_dir.glob("**/*.sol"))
        
        if sample_size:
            import random
            sol_files = random.sample(sol_files, min(sample_size, len(sol_files)))
            print(f"  采样 {len(sol_files)} 个合约进行处理")
        
        contracts = []
        
        for sol_file in tqdm(sol_files, desc="  处理中"):
            self.stats['wild']['total'] += 1
            
            try:
                        
                code = sol_file.read_text(encoding='utf-8', errors='ignore')
                
                        
                if not self.basic_quality_check(code):
                    continue
                
                      
                version = self.extract_solidity_version(code)
                
                      
                functions = self.extract_functions(code)
                
                if not functions:
                    continue
                
                             
                contract = ContractInfo(
                    file_path=str(sol_file),
                    contract_name=sol_file.stem,
                    solidity_version=version,
                    functions=functions,
                    label=None,            
                    metadata={
                        'dataset': 'smartbugs_wild',
                        'ground_truth': False
                    }
                )
                
                contracts.append(contract)
                self.stats['wild']['valid'] += 1
                
            except Exception as e:
                self.stats['wild']['errors'].append({
                    'file': str(sol_file),
                    'error': str(e)
                })
        
        print(f"  ✓ 成功处理: {self.stats['wild']['valid']}/{self.stats['wild']['total']}")
        
                 
        self.save_contracts(contracts, 'wild_processed.json')
        
        return contracts
    
    def extract_solidity_version(self, code: str) -> str:
                            
                               
        patterns = [
            r'pragma\s+solidity\s+\^?([0-9]+\.[0-9]+\.[0-9]+)',
            r'pragma\s+solidity\s+>=?([0-9]+\.[0-9]+\.[0-9]+)',
            r'pragma\s+solidity\s+([0-9]+\.[0-9]+\.[0-9]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                return match.group(1)
        
                      
        return "0.4.25"
    
    def extract_functions(self, code: str) -> List[Dict]:
\
\
           
        functions = []
        
                            
                         
                      
                           
                                              
                       
        pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{'
        
        matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            func_name = match.group(1)
            signature_str = match.group(0)
            
                                
            visibility = 'public'     
            if re.search(r'\bprivate\b', signature_str): visibility = 'private'
            elif re.search(r'\binternal\b', signature_str): visibility = 'internal'
            elif re.search(r'\bexternal\b', signature_str): visibility = 'external'
            
            state_mutability = 'nonpayable'
            if re.search(r'\bpayable\b', signature_str): state_mutability = 'payable'
            elif re.search(r'\bpure\b', signature_str): state_mutability = 'pure'
            elif re.search(r'\bview\b', signature_str): state_mutability = 'view'
            
                                    
            start = match.start()
            func_code = self.extract_function_body(code, start)
            
            functions.append({
                'name': func_name,
                'visibility': visibility,
                'state_mutability': state_mutability,
                'code': func_code,
                'start_pos': start
            })
        
        return functions
    
    def extract_function_body(self, code: str, start_pos: int) -> str:
                         
        brace_count = 0
        in_function = False
        end_pos = start_pos
        
        for i in range(start_pos, len(code)):
            if code[i] == '{':
                brace_count += 1
                in_function = True
            elif code[i] == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    end_pos = i + 1
                    break
        
        return code[start_pos:end_pos]
    
    def basic_quality_check(self, code: str) -> bool:
                    
              
        if len(code) < 100 or len(code) > 100000:
            return False
        
                           
        if 'contract' not in code.lower():
            return False
        
                    
        if 'function' not in code.lower():
            return False
        
        return True
    
    def analyze_versions(self, wild_data: List[ContractInfo], 
                        curated_data: List[ContractInfo]):
                    
        print("\n版本分布分析:")
        
                   
        wild_versions = [c.solidity_version for c in wild_data]
        wild_counter = Counter(wild_versions)
        
        print(f"\nSmartBugs Wild 版本分布 (Top 10):")
        for version, count in wild_counter.most_common(10):
            percentage = (count / len(wild_versions)) * 100
            print(f"  {version}: {count} ({percentage:.1f}%)")
        
                      
        curated_versions = [c.solidity_version for c in curated_data]
        curated_counter = Counter(curated_versions)
        
        print(f"\nSmartBugs Curated 版本分布:")
        for version, count in curated_counter.most_common():
            percentage = (count / len(curated_versions)) * 100
            print(f"  {version}: {count} ({percentage:.1f}%)")
        
                
        version_analysis = {
            'wild': dict(wild_counter),
            'curated': dict(curated_counter)
        }
        
        with open(self.output_dir / 'version_analysis.json', 'w') as f:
            json.dump(version_analysis, f, indent=2)
    
    def filter_wild_by_quality(self, wild_data: List[ContractInfo]) -> List[ContractInfo]:
\
\
           
        print("\n质量过滤...")
        
        filtered = []
        
        for contract in tqdm(wild_data, desc="  过滤中"):
                  
            if self.should_keep_contract(contract):
                filtered.append(contract)
        
        print(f"  ✓ 保留: {len(filtered)}/{len(wild_data)} ({len(filtered)/len(wild_data)*100:.1f}%)")
        
                  
        self.save_contracts(filtered, 'wild_filtered.json')
        
        return filtered
    
    def should_keep_contract(self, contract: ContractInfo) -> bool:
                      
                  
        if not contract.functions or len(contract.functions) == 0:
            return False
        
                   
        if not contract.solidity_version:
            return False
        
                                     
        has_public_func = any(
            f['visibility'] in ['public', 'external'] 
            for f in contract.functions
        )
        if not has_public_func:
            return False
        
                              
        if len(contract.functions) < 2 or len(contract.functions) > 50:
            return False
        
        return True
    
    def create_dataset_splits(self, wild_data: List[ContractInfo], 
                             curated_data: List[ContractInfo]):
\
\
\
\
\
\
           
        print("\n创建数据集划分...")
        
                
        def get_era(version: str) -> str:
            try:
                major, minor, _ = map(int, version.split('.'))
                if major == 0 and minor <= 4:
                    return 'early_legacy'
                elif major == 0 and minor <= 6:
                    return 'late_legacy'
                elif major == 0 and minor <= 7:
                    return 'transition'
                else:
                    return 'modern'
            except:
                return 'unknown'
        
                       
        wild_by_era = defaultdict(list)
        for contract in wild_data:
            era = get_era(contract.solidity_version)
            wild_by_era[era].append(contract)
        
              
        train_data = []
        val_data = []
        test_data = curated_data                 
        
                                           
        train_data.extend(wild_by_era['early_legacy'])
        train_data.extend(wild_by_era['late_legacy'])
        
                         
        val_data.extend(wild_by_era['transition'])
        
                                          
        import random
        modern_samples = random.sample(
            wild_by_era['modern'], 
            min(500, len(wild_by_era['modern']))
        )
        test_data.extend(modern_samples)
        
              
        splits = {
            'train': [c.file_path for c in train_data],
            'val': [c.file_path for c in val_data],
            'test': [c.file_path for c in test_data]
        }
        
        with open(self.output_dir / 'dataset_splits.json', 'w') as f:
            json.dump(splits, f, indent=2)
        
        print(f"  训练集: {len(train_data)} 个合约")
        print(f"  验证集: {len(val_data)} 个合约")
        print(f"  测试集: {len(test_data)} 个合约 (含 {len(curated_data)} 个 Curated)")
        
        return splits
    
    def save_contracts(self, contracts: List[ContractInfo], filename: str):
                         
        output_file = self.output_dir / filename
        
                    
        data = []
        for contract in contracts:
            data.append({
                'file_path': contract.file_path,
                'contract_name': contract.contract_name,
                'solidity_version': contract.solidity_version,
                'num_functions': len(contract.functions),
                'functions': contract.functions,
                'label': contract.label,
                'metadata': contract.metadata
            })
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"  保存到: {output_file}")
    
    def generate_report(self):
                    
        report_file = self.output_dir / 'processing_report.txt'
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("SmartBugs 数据集处理报告\n")
            f.write("="*60 + "\n\n")
            
            f.write("SmartBugs Curated:\n")
            f.write(f"  总数: {self.stats['curated']['total']}\n")
            f.write(f"  成功: {self.stats['curated']['valid']}\n")
            f.write(f"  失败: {len(self.stats['curated']['errors'])}\n\n")
            
            f.write("SmartBugs Wild:\n")
            f.write(f"  总数: {self.stats['wild']['total']}\n")
            f.write(f"  成功: {self.stats['wild']['valid']}\n")
            f.write(f"  失败: {len(self.stats['wild']['errors'])}\n\n")
            
            if self.stats['curated']['errors']:
                f.write("Curated 错误列表:\n")
                for error in self.stats['curated']['errors'][:10]:
                    f.write(f"  {error['file']}: {error['error']}\n")
            
            if self.stats['wild']['errors']:
                f.write("\nWild 错误列表 (前10个):\n")
                for error in self.stats['wild']['errors'][:10]:
                    f.write(f"  {error['file']}: {error['error']}\n")
        
        print(f"\n报告已生成: {report_file}")


      
if __name__ == "__main__":
    processor = SmartBugsProcessor(
        wild_dir='/path/to/smartbugs-wild',
        curated_dir='/path/to/smartbugs-curated',
        output_dir='./processed_smartbugs'
    )
    
                      
    wild_data, curated_data = processor.process_both_datasets()
