\
\
\
\
\
\
\
\
   

import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from tqdm import tqdm
from collections import defaultdict

from src.tools.slither_manager import SlitherManager, TARGET_DETECTORS

class VulnerabilityCollector:
\
\
       

                          
    DETECTOR_TO_VULN_TYPE = {
                                               
        'reentrancy-eth': 'reentrancy',
        'reentrancy-no-eth': 'reentrancy',
        'reentrancy-benign': 'reentrancy',
        'reentrancy-events': 'reentrancy',
        'reentrancy-unlimited-gas': 'reentrancy',
        
                                                   
        'suicidal': 'access_control',
        'unprotected-upgrade': 'access_control',
        'arbitrary-send-eth': 'access_control',
        'arbitrary-send-erc20': 'access_control',
        'arbitrary-send-erc20-permit': 'access_control',
        'controlled-delegatecall': 'access_control',
        'controlled-array-length': 'access_control',
        'tx-origin': 'access_control',
        'protected-vars': 'access_control',
        'gelato-unprotected-randomness': 'access_control',
        
                                               
        'incorrect-shift': 'arithmetic',
        'incorrect-exp': 'arithmetic',
        'divide-before-multiply': 'arithmetic',
        
                                                              
        'unchecked-lowlevel': 'unchecked_return',
        'unchecked-send': 'unchecked_return',
        'unchecked-transfer': 'unchecked_return',
        'unused-return': 'unchecked_return',
        
                                                              
        'uninitialized-state': 'uninitialized_storage',
        'uninitialized-storage': 'uninitialized_storage',
        'uninitialized-local': 'uninitialized_storage',
        'uninitialized-fptr-cst': 'uninitialized_storage',
        
                                                              
        'timestamp': 'timestamp_dependence',
        'weak-prng': 'bad_randomness',
        
                                                 
        'delegatecall-loop': 'delegatecall',
        
                                                  
        'locked-ether': 'locked_ether',
        
                                                               
        'msg-value-loop': 'msg_value_loop',
        
                                              
        'shadowing-state': 'shadowing',
        'shadowing-abstract': 'shadowing',
        'shadowing-builtin': 'shadowing',
        'shadowing-local': 'shadowing',
        
                                                    
        'abiencoderv2-array': 'abi_encoding',
        'encode-packed-collision': 'abi_encoding',
        
                                                   
        'array-by-reference': 'storage_issue',
        'storage-array': 'storage_issue',
        'mapping-deletion': 'storage_issue',
        
                                                 
        'incorrect-equality': 'logic_error',
        'tautological-compare': 'logic_error',
        'tautology': 'logic_error',
        'boolean-cst': 'logic_error',
        'incorrect-unary': 'logic_error',
        'boolean-equal': 'logic_error',
        
                                                     
        'erc20-interface': 'interface_issue',
        'erc721-interface': 'interface_issue',
        
                                                   
        'pyth-unchecked-confidence': 'oracle_issue',
        'pyth-unchecked-publishtime': 'oracle_issue',
        'chronicle-unchecked-price': 'oracle_issue',
        'chainlink-feed-registry': 'oracle_issue',
        
                                                         
        'multiple-constructors': 'constructor_issue',
        'reused-constructor': 'constructor_issue',
        'void-cst': 'constructor_issue',
        
                                                         
        'incorrect-return': 'return_value_issue',
        'return-leave': 'return_value_issue',
        
                                                         
        'pyth-deprecated-functions': 'deprecated_function',
        'optimism-deprecation': 'deprecated_function',
        'deprecated-standards': 'deprecated_standard',
        
                                                       
        'missing-zero-check': 'missing_validation',
        
                                                   
        'events-access': 'missing_event',
        'events-maths': 'missing_event',
        'erc20-indexed': 'event_issue',
        
                                                      
        'calls-loop': 'gas_optimization',
        'costly-loop': 'gas_optimization',
        'cache-array-length': 'gas_optimization',
        'constable-states': 'gas_optimization',
        'external-function': 'gas_optimization',
        'immutable-states': 'gas_optimization',
        'var-read-using-this': 'gas_optimization',
        
                                           
        'assembly': 'assembly_usage',
        'constant-function-asm': 'assembly_issue',
        'low-level-calls': 'low_level_call',
        
                                                 
        'cyclomatic-complexity': 'code_quality',
        'redundant-statements': 'code_quality',
        'too-many-digits': 'code_quality',
        'dead-code': 'dead_code',
        'unused-state': 'unused_variable',
        
                                                    
        'enum-conversion': 'type_conversion',
        
                                                      
        'constant-function-state': 'state_mutability',
        
                                                 
        'name-reused': 'naming_issue',
        'naming-convention': 'naming_convention',
        'public-mappings-nested': 'visibility_issue',
        'rtlo': 'malicious_code',
        'codex': 'other',
        'domain-separator-collision': 'signature_collision',
        'unused-write': 'unused_write',
        'out-of-order-retryable': 'transaction_order',
        'incorrect-modifier': 'modifier_issue',
        'variable-scope': 'scope_issue',
        'return-bomb': 'gas_griefing',
        'assert-state-change': 'assertion_issue',
        'function-init-state': 'initialization_issue',
        'incorrect-using-for': 'using_for_issue',
        'missing-inheritance': 'inheritance_issue',
        'pragma': 'pragma_issue',
        'solc-version': 'compiler_version',
        'unimplemented-functions': 'incomplete_implementation',
    }
    
    def __init__(self, slither, debug: bool = False):
        self.slither = slither
        self.detector_mapping = self.DETECTOR_TO_VULN_TYPE
        self.debug = debug
        self._register_detectors()

    def _register_detectors(self) -> None:
                        
        from slither.detectors import all_detectors

        for detector_name in TARGET_DETECTORS:
            if hasattr(all_detectors, detector_name):
                detector = getattr(all_detectors, detector_name)
                if detector:
                    self.slither.register_detector(detector)
                elif self.debug:
                    print(f"Detector {detector_name} not registered")
            elif self.debug:
                print(f"Detector {detector_name} not found")

    def collect_vulnerabilities(self) -> Dict[str, List[Dict]]:
                  
        vulnerabilities_by_function = defaultdict(list)
        results = self.slither.run_detectors()

        for result in self._flatten_results(results):
            detector = result['check']
            impact = result['impact']
            description = result['description']

            vuln_type = self.detector_mapping.get(detector, detector)
            affected_functions = self._extract_affected_functions(result)

            for func_id in affected_functions:
                vulnerabilities_by_function[func_id].append({
                    'type': vuln_type,
                    'detector': detector,
                    'severity': impact,
                    'description': description,
                })

        return dict(vulnerabilities_by_function)

    @staticmethod
    def _flatten_results(results) -> List[Dict]:
                       
        flattened_results = []
        for item in results:
            if isinstance(item, list):
                flattened_results.extend(item)
            else:
                flattened_results.append(item)
        return flattened_results

    @staticmethod
    def _extract_affected_functions(detection_result: Dict) -> Set[str]:
\
\
\
\
\
           
        affected_functions = set()
        
        elements = detection_result.get('elements', [])
        for element in elements:
                          
            if element.get('type') in ['function', 'node', 'variable']:
                           
                contract_name = element.get('type_specific_fields', {}).get('parent', {}).get('name', '')
                function_name = element.get('name', '')
                
                                             
                if element.get('type') in ['node', 'variable']:
                                              
                    source_mapping = element.get('source_mapping', {})
                    if 'parent_function' in source_mapping:
                        function_name = source_mapping['parent_function'].get('name', '')
                
                                                   
                if not contract_name and 'type_specific_fields' in element:
                    parent = element['type_specific_fields'].get('parent', {})
                    if parent.get('type') == 'contract':
                        contract_name = parent.get('name', '')
                
                if contract_name and function_name:
                    func_id = f"{contract_name}.{function_name}"
                    affected_functions.add(func_id)
        
        return affected_functions

class FunctionVulnerabilityLabeler:
\
\
\
\
\
\
       
        
    def __init__(self, debug: bool = False):
\
\
\
\
\
           
        self.manager = SlitherManager(debug=debug)
        self.debug = debug
    
    def label_functions_in_contract(self, 
                                    contract_file: str,
                                    include_safe: bool = True) -> List[Dict]:
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
\
\
           
        labels = []
        
        try:
            with self.manager.analyze_contract(contract_file) as slither:
                                     
                if slither is None:
                    if self.debug:
                        print(f"Failed to analyze {contract_file}")
                    return labels
                
                                    
                collector = VulnerabilityCollector(
                    slither=slither,
                    debug=self.debug,
                )
                vulnerabilities_by_function = collector.collect_vulnerabilities()
                
                              
                for contract in slither.contracts:
                    for function in contract.functions:
                                
                        if function.is_constructor or function.is_fallback or function.is_receive:
                            continue
                        
                                  
                        func_id = f"{contract.name}.{function.name}"
                        
                                    
                        func_vulns = vulnerabilities_by_function.get(func_id, [])
                        
                                          
                        if not include_safe and not func_vulns:
                            continue
                        
                                    
                        vuln_types = list(set([v['type'] for v in func_vulns]))
                        
                              
                        label = {
                            'contract_file': contract_file,
                            'contract_name': contract.name,
                            'function_name': function.name,
                            'function_signature': function.signature_str,
                            'function_code': self._get_function_code(function),
                            'is_vulnerable': len(func_vulns) > 0,
                            'vulnerability_types': vuln_types,
                            'vulnerability_count': len(vuln_types),
                            'vulnerability_details': func_vulns,
                        }
                        
                        labels.append(label)
        
        except Exception as e:
            if self.debug:
                print(f"Error labeling {contract_file}: {e}")
                import traceback
                traceback.print_exc()
        print(labels)
        return labels
    
    def _get_function_code(self, function) -> str:
                      
        try:
            if hasattr(function, 'source_mapping') and function.source_mapping:
                content = function.source_mapping.content
                if content:
                    return content.decode('utf-8') if isinstance(content, bytes) else str(content)
            
                         
            if hasattr(function, 'source_mapping'):
                filename = function.source_mapping.filename.absolute
                start = function.source_mapping.start
                length = function.source_mapping.length
                
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(start)
                    return f.read(length)
        except Exception as e:
            if self.debug:
                print(f"Warning: Failed to extract function code: {e}")
        
        return ""
    
    def batch_label_contracts(self,
                             contract_files: List[str],
                             output_file: str,
                             include_safe: bool = True,
                             save_interval: int = 100,
                             debug: bool = False):
\
\
\
\
\
\
\
\
           
        all_labels = []
        stats = {
            'total_contracts': len(contract_files),
            'processed_contracts': 0,
            'failed_contracts': 0,
            'total_functions': 0,
            'vulnerable_functions': 0,
            'safe_functions': 0,
            'vulnerability_distribution': defaultdict(int),
            'failed_files': []
        }
        
        for i, contract_file in enumerate(tqdm(contract_files, desc="标注合约")):
            try:
                labels = self.label_functions_in_contract(contract_file, include_safe)
                
                if labels:
                    all_labels.extend(labels)
                    stats['processed_contracts'] += 1
                    stats['total_functions'] += len(labels)
                    
                    for label in labels:
                        if label['is_vulnerable']:
                            stats['vulnerable_functions'] += 1
                            for vuln_type in label['vulnerability_types']:
                                stats['vulnerability_distribution'][vuln_type] += 1
                        else:
                            stats['safe_functions'] += 1
                else:
                    stats['failed_contracts'] += 1
                    stats['failed_files'].append(contract_file)
                
                      
                if (i + 1) % save_interval == 0:
                    self._save_results(all_labels, stats, output_file, partial=True)
                    if self.debug:
                        print(f"\n已保存中间结果: {i+1}/{len(contract_files)}")
            
            except Exception as e:
                stats['failed_contracts'] += 1
                stats['failed_files'].append(contract_file)
                if self.debug:
                    print(f"\nError processing {contract_file}: {e}")
        
              
        self._save_results(all_labels, stats, output_file, partial=False)
        
              
        self._print_stats(stats)
        
        return all_labels, stats
    
    def _save_results(self, labels: List[Dict], stats: Dict, output_file: str, partial: bool = False):
                  
              
        labels_file = output_file if not partial else output_file.replace('.json', '_partial.json')
        with open(labels_file, 'w', encoding='utf-8') as f:
            json.dump(labels, f, indent=2, ensure_ascii=False)
        
              
        stats_copy = dict(stats)
        stats_copy['vulnerability_distribution'] = dict(stats_copy['vulnerability_distribution'])
        stats_file = output_file.replace('.json', '_stats.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats_copy, f, indent=2, ensure_ascii=False)
    
    def _print_stats(self, stats: Dict):
                    
        print("\n" + "=" * 70)
        print("函数级漏洞标注统计")
        print("=" * 70)
        print(f"总合约数: {stats['total_contracts']}")
        print(f"  成功处理: {stats['processed_contracts']}")
        print(f"  处理失败: {stats['failed_contracts']}")
        print(f"\n总函数数: {stats['total_functions']}")
        print(f"  有漏洞: {stats['vulnerable_functions']} ({stats['vulnerable_functions']/max(stats['total_functions'],1)*100:.1f}%)")
        print(f"  无漏洞: {stats['safe_functions']} ({stats['safe_functions']/max(stats['total_functions'],1)*100:.1f}%)")
        
        if stats['vulnerability_distribution']:
            print(f"\n漏洞类型分布:")
            sorted_vulns = sorted(
                stats['vulnerability_distribution'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for vuln_type, count in sorted_vulns:
                percentage = count / stats['vulnerable_functions'] * 100
                print(f"  {vuln_type}: {count} ({percentage:.1f}%)")
        
        if stats['failed_files'] and len(stats['failed_files']) <= 10:
            print(f"\n处理失败的文件:")
            for f in stats['failed_files']:
                print(f"  - {f}")
        elif stats['failed_files']:
            print(f"\n处理失败的文件: {len(stats['failed_files'])} 个（见统计文件）")


      
def label_single_contract(contract_file: str, 
                         include_safe: bool = True,
                         debug: bool = True) -> List[Dict]:
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
       
    labeler = FunctionVulnerabilityLabeler(debug=debug)
    return labeler.label_functions_in_contract(contract_file, include_safe)


def label_dataset(contract_dir: str,
                 output_file: str,
                 include_safe: bool = True,
                 pattern: str = "**/*.sol",
                 debug: bool = False) -> tuple:
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
       
              
    contract_files = list(Path(contract_dir).glob(pattern))
    print(f"找到 {len(contract_files)} 个合约文件")
    
          
    labeler = FunctionVulnerabilityLabeler(debug=debug)
    return labeler.batch_label_contracts(
        contract_files=[str(f) for f in contract_files],
        output_file=output_file,
        include_safe=include_safe,
        debug=debug
    )


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  单个合约:")
        print("    python function_labeler.py single <contract_file> [--no-safe]")
        print("")
        print("  批量标注:")
        print("    python function_labeler.py batch <contract_dir> <output_file> [--no-safe]")
        print("")
        print("示例:")
        print("    python function_labeler.py single contract.sol")
        print("    python function_labeler.py batch ./contracts labels.json")
        sys.exit(1)
    
    command = sys.argv[1]
    include_safe = '--no-safe' not in sys.argv
    
    if command == "single":
        if len(sys.argv) < 3:
            print("用法: python function_labeler.py single <contract_file>")
            sys.exit(1)
        
        contract_file = sys.argv[2]
        
        print(f"标注合约: {contract_file}")
        labels = label_single_contract(contract_file, include_safe, debug=True)
        
        print(f"\n找到 {len(labels)} 个函数:")
        for label in labels:
            status = "⚠️ " if label['is_vulnerable'] else "✓ "
            vulns = ", ".join(label['vulnerability_types']) if label['vulnerability_types'] else "无漏洞"
            print(f"{status}{label['function_name']}: {vulns}")
        
                   
        output_file = contract_file.replace('.sol', '_labels.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(labels, f, indent=2, ensure_ascii=False)
        print(f"\n标签已保存到: {output_file}")
    
    elif command == "batch":
        if len(sys.argv) < 4:
            print("用法: python function_labeler.py batch <contract_dir> <output_file>")
            sys.exit(1)
        
        contract_dir = sys.argv[2]
        output_file = sys.argv[3]
        
        print(f"批量标注目录: {contract_dir}")
        print(f"输出文件: {output_file}")
        print(f"包含安全函数: {include_safe}")
        
        labels, stats = label_dataset(contract_dir, output_file, include_safe, debug=False)
        
        print(f"\n✓ 完成!")
        print(f"  标签文件: {output_file}")
        print(f"  统计文件: {output_file.replace('.json', '_stats.json')}")
    
    else:
        print(f"未知命令: {command}")
        sys.exit(1)