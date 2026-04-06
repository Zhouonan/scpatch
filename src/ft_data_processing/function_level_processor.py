\
\
\
   

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import ast as python_ast
from tqdm import tqdm
from src.tools.slither_manager import SlitherManager
from src.tools.function_vul_labeler import VulnerabilityCollector

try:
    from slither.slither import Slither
    from slither.core.declarations import Function
    SLITHER_AVAILABLE = True
except ImportError:
    print("Warning: Slither not available. Using regex-based parsing.")
    SLITHER_AVAILABLE = False

try:
    import solcx
    SOLCX_AVAILABLE = True
except ImportError:
    print("Warning: py-solc-x not available. Version switching disabled.")
    SOLCX_AVAILABLE = False


@dataclass
class FunctionContext:
                       
          
    function_code: str
    function_name: str
    function_signature: str
    start_line: int
    end_line: int
    
           
    caller_functions: List[Dict]            
    called_functions: List[Dict]            
    
           
    contract_context: Dict
    
           
    ast_features: Dict
    
         
    metadata: Dict
    
                            
    label: Optional[Dict]

                 
    slither_result: Dict

    

class FunctionLevelProcessor:
                
    
    def __init__(self, use_slither: bool = True, debug: bool = False, 
                 enable_deduplication: bool = True,
                 enable_filtering: bool = True):
\
\
\
\
\
\
           
        self.use_slither = use_slither and SLITHER_AVAILABLE
        self.debug = debug
        self.enable_deduplication = enable_deduplication
        self.enable_filtering = enable_filtering
        
                     
        self._installed_versions = set()
                        
        self._version_to_path = {}
        self.slither_manager = SlitherManager(debug = debug)
        
                                                     
        self._dedup_table = {}
              
        self._stats = {
            'total_extracted': 0,
            'filtered_out': 0,
            'deduplicated': 0,
            'final_count': 0
        }

    def should_filter_function(self, function, func_code: str) -> Tuple[bool, str]:
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
           
        if not self.enable_filtering:
            return False, ""
                           
                                                  
                              
        func_code_stripped = func_code.strip()
        lines = func_code_stripped.split('\n')
        line_count = len(lines)
        
                                    
                               
                                                  
                                                   
                                                   
                                                   
                                                 
                                                     
                                                          
                                                    
                                                    
                                                 
                                                 
                                                    
                                                  
           
        
                                           
                                               
                                                
        
                             
        if function.name.startswith('slitherConstructor'):
            return True, "slither_internal"
        
                                    
                               
                                          
                                      
        
                                    
                                 
                                            
                                     
        
                                
                                           
                                                                  
                                   
                                                                                                      
                                                                       
                                  
                                                                                              
                                                   
        
                                    
                           
                          
                                                                                                           
                                                         
            
                                      
                                                                                            
                                  
                                                                                                     
                                                 
        
                                   
                                                                 
                                                                     
                                                                                        
                                        
        
                                            
                                                          
                                         
                                                                          
                                                                    
                                                                                                                        
            
                                                                              
                                               
        
                               
                               
                             
                                                   
                                                    
                                 
                                                          
                             
                                                                                                                      
                                              
        
                     
        return False, ""
    
    def compute_function_hash(self, func_code: str) -> str:
                        
        import hashlib
                          
        normalized = func_code.strip()
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def calculate_priority(self, func_context, label: Optional[Dict]) -> int:
\
\
\
\
           
        priority = 0
        
                             
        if func_context.metadata.get('dataset') == 'curated':
            priority += 1000
        
                         
        if label and label.get('is_vulnerable'):
            priority += 100
            
                                        
            vuln_count = label.get('vulnerability_count', 0)
            priority += vuln_count * 10
        
                                                 
        if func_context.slither_result and func_context.slither_result.get('is_vulnerable'):
            priority += 50
            priority += func_context.slither_result.get('vulnerability_count', 0) * 5

        return priority
    
    def try_add_function(self, func_context) -> bool:
\
\
\
\
\
           
        if not self.enable_deduplication:
            return True            
        
        func_code = func_context.function_code
        code_hash = self.compute_function_hash(func_code)
        label = func_context.label or {}
        priority = self.calculate_priority(func_context, label)
        
        if code_hash not in self._dedup_table:
                      
            self._dedup_table[code_hash] = (func_context, priority)
            return True
        else:
                       
            existing_func, existing_priority = self._dedup_table[code_hash]
            
            if priority > existing_priority:
                           
                self._dedup_table[code_hash] = (func_context, priority)
                self._stats['deduplicated'] += 1
                return True
            else:
                        
                self._stats['deduplicated'] += 1
                return False
    
    def get_final_functions(self) -> List[FunctionContext]:
                          
        if not self.enable_deduplication:
            raise RuntimeError("Deduplication not enabled")
        
        return [func for func, _ in self._dedup_table.values()]
    
    def print_stats(self):
                    
        print(f"\n  【函数处理统计】")
        print(f"    提取总数: {self._stats['total_extracted']}")
        print(f"    过滤掉: {self._stats['filtered_out']}")
        print(f"    去重: {self._stats['deduplicated']}")
        print(f"    最终保留: {self._stats['final_count']}")
        if self._stats['total_extracted'] > 0:
            reduction = (1 - self._stats['final_count'] / self._stats['total_extracted']) * 100
            print(f"    减少: {reduction:.1f}%")
    
    def process_contract_to_functions(self, 
                                     contract_file: str,
                                     contract_info: Optional[Dict] = None) -> List[FunctionContext]:
\
\
\
\
\
\
\
\
\
           
        if self.use_slither:
            return self._process_with_slither(contract_file, contract_info)
        else:
            return self._process_with_regex(contract_file, contract_info)
    
    def _process_with_slither(self, 
                             contract_file: str, 
                             contract_info: Optional[Dict]) -> List[FunctionContext]:
                             
        function_contexts = []
        
        try:
            with self.slither_manager.analyze_contract(contract_file) as slither:
                if not slither:
                    print(f"Failed to analyze contract {contract_file}")
                    return []
                
                collector = VulnerabilityCollector(
                            slither=slither,
                            debug=self.debug,
                        )
                
                for contract_idx, contract in enumerate(slither.contracts):
                    try:
                        print(f"           Processing contract {contract_idx + 1}/{len(slither.contracts)}: {contract.name}")
                        
                               
                        try:
                            call_graph = self._build_call_graph(contract)
                        except Exception as e:
                            print(f"    Error building call graph: {type(e).__name__}: {e}")
                            if self.debug:
                                import traceback
                                traceback.print_exc()
                            continue
                        
                                 
                        try:
                            contract_context = self._extract_contract_context(contract)
                        except Exception as e:
                            print(f"    Error extracting contract context: {type(e).__name__}: {e}")
                            import traceback
                            traceback.print_exc()
                            continue
                        
                              
                        
                        vulnerabilities_by_function = collector.collect_vulnerabilities()

                                
                        for func_idx, function in enumerate(contract.functions):
                            try:
                                self._stats['total_extracted'] += 1
                                
                                             
                                if function.is_constructor or function.is_fallback:
                                    self._stats['filtered_out'] += 1
                                    continue

                                func_id = f"{contract.name}.{function.name}"

                                            
                                func_vulns = vulnerabilities_by_function.get(func_id, [])
                                
                                                    
                                                    
                                              

                                            
                                vuln_types = list(set([v['type'] for v in func_vulns])) if func_vulns else []
                                
                                             
                                slither_result = {
                                    'is_vulnerable': len(func_vulns) > 0,
                                    'vulnerability_types': vuln_types,
                                    'vulnerability_count': len(vuln_types),
                                    'vulnerability_details': func_vulns
                                }

                                         
                                func_context = self._build_function_context(
                                    function=function,
                                    call_graph=call_graph,
                                    contract_context=contract_context,
                                    contract_info=contract_info,
                                    slither_result=slither_result
                                )
                                
                                if not func_context:
                                    continue
                                
                                                
                                should_filter, filter_reason = self.should_filter_function(
                                    function, func_context.function_code
                                )
                                if should_filter:
                                    self._stats['filtered_out'] += 1
                                    if self.debug:
                                        print(f"      Filtered: {func_id} ({filter_reason})")
                                    continue
                                
                                           
                                if self.enable_deduplication:
                                    if self.try_add_function(func_context):
                                                            
                                                     
                                        pass
                                else:
                                              
                                    function_contexts.append(func_context)
                                    self._stats['final_count'] += 1
                            
                            except Exception as e:
                                func_name = getattr(function, 'name', f'function_{func_idx}')
                                print(f"    Error processing function {func_name}: {type(e).__name__}: {e}")
                                import traceback
                                traceback.print_exc()
                                continue

                        

                    except Exception as e:
                        contract_name = getattr(contract, 'name', f'contract_{contract_idx}')
                        print(f"  Error processing contract {contract_name}: {type(e).__name__}: {e}")
                        import traceback
                        traceback.print_exc()
                        continue
        
        except Exception as e:
            print(f"Error processing {contract_file} with Slither: {type(e).__name__}: {e}")
            print(f"Detailed traceback:")
            import traceback
            traceback.print_exc()
                        
            return self._process_with_regex(contract_file, contract_info)
        
                            
        if self.enable_deduplication:
                                
                                                         
            return function_contexts                  
        else:
            return function_contexts
    
    def _process_with_regex(self, 
                           contract_file: str, 
                           contract_info: Optional[Dict]) -> List[FunctionContext]:
                            
        function_contexts = []
        
        try:
            with open(contract_file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
                    
            functions = self._extract_functions_regex(code)
            
                      
            call_graph = self._build_simple_call_graph(functions)
            
                     
            contract_context = self._extract_contract_context_regex(code)
            
                        
            for func_name, func_data in functions.items():
                self._stats['total_extracted'] += 1

                func_context = self._build_function_context_regex(
                    func_name=func_name,
                    func_data=func_data,
                    call_graph=call_graph,
                    contract_context=contract_context,
                    contract_file=contract_file,
                    contract_info=contract_info
                )
                
                if func_context:
                                                
                    if self.enable_filtering:
                                                                              
                        class _DummyFunc:
                            def __init__(self, name: str, metadata: Dict, visibility: str, state_mutability: str):
                                self.name = name
                                self.metadata = metadata or {}
                                self.visibility = visibility
                                self.state_mutability = state_mutability
                                self.view = state_mutability == 'view'
                                self.pure = state_mutability == 'pure'
                                self.payable = state_mutability == 'payable'

                        dummy = _DummyFunc(
                            name=func_name,
                            metadata=func_context.metadata or {},
                            visibility=(func_context.metadata or {}).get('visibility', 'unknown'),
                            state_mutability=(func_context.metadata or {}).get('state_mutability', 'unknown'),
                        )
                        should_filter, _reason = self.should_filter_function(dummy, func_context.function_code)
                        if should_filter:
                            self._stats['filtered_out'] += 1
                            continue

                    if self.enable_deduplication:
                                                                         
                        self.try_add_function(func_context)
                    else:
                        function_contexts.append(func_context)
                        self._stats['final_count'] += 1
        
        except Exception as e:
            print(f"Error processing {contract_file} with regex: {e}")
        
        return function_contexts
    
    def _build_call_graph(self, contract) -> Dict[str, Dict]:
                                
        call_graph = {}
        
        for func_idx, function in enumerate(contract.functions):
            func_name = getattr(function, 'name', f'function_{func_idx}')
            callers = []
            callees = []
            
                  
            for caller in function.reachable_from_functions:
                if caller.contract == contract:
                    callers.append({
                        'name': caller.name,
                        'signature': caller.signature_str,
                        'visibility': str(caller.visibility)
                    })
            
                   
                                                                          
                                           
            for callee in (getattr(function, 'internal_calls', []) or []) + (getattr(function, 'external_calls_as_expressions', []) or []):
                callee_name = None
                if hasattr(callee, 'name'):
                    callee_name = callee.name
                elif hasattr(callee, 'function_name'):
                    callee_name = callee.function_name
                elif hasattr(callee, 'called'):
                                               
                    callee_name = getattr(getattr(callee, 'called', None), 'name', None)

                if not callee_name:
                    continue

                callees.append({
                    'name': callee_name,
                    'type': 'internal' if callee in (getattr(function, 'internal_calls', []) or []) else 'external'
                })
            
            call_graph[function.name] = {
                'callers': callers,
                'callees': callees
            }
        
        return call_graph
    
    def _build_simple_call_graph(self, functions: Dict) -> Dict[str, Dict]:
                            
        call_graph = {}
        
        for func_name, func_data in functions.items():
            callers = []
            callees = []
            
            func_code = func_data['code']
            
                          
            for other_name in functions.keys():
                if other_name != func_name and other_name in func_code:
                    callees.append({
                        'name': other_name,
                        'type': 'internal'
                    })
            
                          
            for other_name, other_data in functions.items():
                if other_name != func_name and func_name in other_data['code']:
                    callers.append({
                        'name': other_name,
                        'signature': other_name,
                        'visibility': 'unknown'
                    })
            
            call_graph[func_name] = {
                'callers': callers,
                'callees': callees
            }
        
        return call_graph
    
    def _extract_contract_context(self, contract) -> Dict:
                                 
        
                     
        state_variables = []
        for var in contract.state_variables:
            try:
                                    
                code = var.source_mapping.content if hasattr(var, 'source_mapping') and var.source_mapping else f"{var.type} {var.visibility} {var.name};"
                state_variables.append({
                    'name': var.name,
                    'type': str(var.type),
                    'visibility': str(var.visibility),
                    'code': code
                })
            except Exception:
                              
                state_variables.append({
                    'name': var.name,
                    'type': str(var.type),
                    'visibility': str(var.visibility),
                    'code': f"// Error extraction: {var.name}"
                })

                   
        modifiers = []
        for mod in contract.modifiers:
            try:
                code = mod.source_mapping.content if hasattr(mod, 'source_mapping') and mod.source_mapping else f"modifier {mod.name}() {{ _ ;}}"
                modifiers.append({
                    'name': mod.name,
                    'code': code
                })
            except Exception:
                pass

                 
        structures = []
        if hasattr(contract, 'structures'):
            for struct in contract.structures:
                try:
                    code = struct.source_mapping.content if hasattr(struct, 'source_mapping') and struct.source_mapping else f"struct {struct.name} {{ ... }}"
                    structures.append({
                        'name': struct.name,
                        'code': code
                    })
                except Exception:
                    pass

                
        events = []
        if hasattr(contract, 'events'):
            for event in contract.events:
                try:
                    code = event.source_mapping.content if hasattr(event, 'source_mapping') and event.source_mapping else f"event {event.name}(...);"
                    events.append({
                        'name': event.name,
                        'code': code
                    })
                except Exception:
                    pass

        return {
            'contract_name': contract.name,
            'inheritance': [str(base) for base in contract.inheritance],
            'state_variables': state_variables,
            'modifiers': modifiers,
            'structures': structures,
            'events': events,
            'num_functions': len(contract.functions)
        }
    
    def _extract_contract_context_regex(self, code: str) -> Dict:
                            
               
        contract_name = 'Unknown'
        match = re.search(r'contract\s+(\w+)', code)
        if match:
            contract_name = match.group(1)
        
              
        inheritance = []
        match = re.search(r'contract\s+\w+\s+is\s+([^{]+)', code)
        if match:
            inheritance = [i.strip() for i in match.group(1).split(',')]
        
                
        state_vars = re.findall(r'(uint|address|bool|string|mapping)\s+(\w+)\s*;', code)
        
               
        modifiers = re.findall(r'modifier\s+(\w+)', code)
        
        return {
            'contract_name': contract_name,
            'inheritance': inheritance,
            'state_variables': [
                {'name': name, 'type': typ}
                for typ, name in state_vars
            ],
            'modifiers': modifiers
        }
    
    def _safe_get_state_mutability(self, function) -> str:
                          
        try:
                                                 
            if hasattr(function, 'state_mutability'):
                return str(function.state_mutability)
            
                           
            if hasattr(function, 'pure') and function.pure:
                return 'pure'
            elif hasattr(function, 'view') and function.view:
                return 'view'
            elif hasattr(function, 'payable') and function.payable:
                return 'payable'
            else:
                return 'nonpayable'
        except:
                 
            return 'nonpayable'
        
    def _build_function_context(self, 
                               function,
                               call_graph: Dict,
                               contract_context: Dict,
                               contract_info: Optional[Dict],
                               slither_result: Dict) -> Optional[FunctionContext]:
                                
        try:
            func_name = function.name
            
                                              
            callers = call_graph.get(func_name, {}).get('callers', [])[:3]
            
                                                   
            called_funcs = []
            seen_callees = set()
            
                                       
                                                      
            try:
                              
                raw_callees = []
                if hasattr(function, 'internal_calls'):
                    raw_callees.extend(function.internal_calls)
                
                for callee in raw_callees:
                                 
                    if callee == function:
                        continue

                                                                                                  
                    callee_name = getattr(callee, 'name', None) or getattr(callee, 'function_name', None)
                    if not callee_name:
                        continue

                    callee_contract = getattr(callee, 'contract', None)
                    callee_contract_name = getattr(callee_contract, 'name', None) or 'unknown'

                    callee_id = f"{callee_contract_name}.{callee_name}"
                    if callee_id in seen_callees:
                        continue
                    seen_callees.add(callee_id)

                    try:
                               
                        code = ""
                        if hasattr(callee, 'source_mapping') and callee.source_mapping:
                            code = callee.source_mapping.content
                        
                        if not code:
                                        
                            code = f"function {callee_name}(...) {{ ... }}"

                        called_funcs.append({
                            'name': callee_name,
                            'contract_name': callee_contract_name,
                            'type': 'internal',
                            'code': code
                        })
                    except Exception:
                        continue
            except Exception as e:
                if self.debug:
                    print(f"Warning: Failed to extract callees for {func_name}: {e}")
            
                                     
            called_funcs = called_funcs[:10]
            
                      
            try:
                func_code = function.source_mapping.content if hasattr(function, 'source_mapping') and function.source_mapping else f"function {func_name}() {{}}"
            except:
                func_code = f"function {func_name}() {{}}"
            
                     
            ast_features = self._extract_ast_features_slither(function)
            
                           
            caller_funcs = []
            for caller_info in callers:
                caller_funcs.append({
                    'name': caller_info.get('name', 'unknown'),
                    'signature': caller_info.get('signature', caller_info.get('name', 'unknown')),
                    'code_snippet': f"// Caller: {caller_info.get('signature', caller_info.get('name', 'unknown'))}"
                })
            
                                           
                      
                               
                                             
            
                      
            try:
                func_signature = function.signature_str if hasattr(function, 'signature_str') else func_name
            except:
                func_signature = func_name
            
                 
                                                                                              
            contract_file = 'unknown'
            try:
                if hasattr(function, 'contract') and hasattr(function.contract, 'source_mapping'):
                    filename_obj = getattr(function.contract.source_mapping, 'filename', None)
                    if filename_obj is not None:
                                                                            
                        if hasattr(filename_obj, 'relative') and filename_obj.relative:
                            contract_file = str(filename_obj.relative)
                        elif hasattr(filename_obj, 'short') and filename_obj.short:
                            contract_file = str(filename_obj.short)
                        elif hasattr(filename_obj, 'absolute') and filename_obj.absolute:
                            contract_file = str(filename_obj.absolute)
                        else:
                            contract_file = str(filename_obj)
            except Exception:
                contract_file = 'unknown'

            metadata = {
                'contract_file': contract_file,
                'function_name': func_name,
                'visibility': str(function.visibility) if hasattr(function, 'visibility') else 'unknown',
                'state_mutability': self._safe_get_state_mutability(function),
                'is_payable': function.payable if hasattr(function, 'payable') else False
            }
            
                    
            if contract_info:
                metadata.update(contract_info)

                                 
                      
            all_events = contract_context.get('events', [])
            used_events = []
            
                                      
                               
            search_scope = func_code
            for callee in called_funcs:
                search_scope += "\n" + callee.get('code', '')
            
            for event in all_events:
                event_name = event['name']
                                                
                if f"emit {event_name}" in search_scope or f"{event_name}(" in search_scope:
                    used_events.append(event)
            
                                                      
            func_contract_context = contract_context.copy()
            func_contract_context['events'] = used_events
            
                           
            func_label = None
            start_line = 1       
            end_line = 1         
            
            if contract_info and contract_info.get('functions'):
                                                           
                for func_info in contract_info['functions']:
                    if func_info.get('name') == func_name:
                                
                        lines = func_info.get('lines', [])
                        if lines and len(lines) >= 2:
                            start_line = lines[0]
                            end_line = lines[1]
                        
                                  
                        if func_info.get('is_vulnerable'):
                            func_label = {
                                'is_vulnerable': True,
                                'vulnerability_types': [v['category'] for v in func_info.get('vulnerabilities', [])],
                                'vulnerability_details': func_info.get('vulnerabilities', []),
                                'source': 'ground_truth'
                            }
                        else:
                            func_label = {
                                'is_vulnerable': False,
                                'vulnerability_types': [],
                                'vulnerability_details': [],
                                'source': 'ground_truth'
                            }
                        break
            
                                                        
                                                       
                                       
            
            return FunctionContext(
                function_code=func_code,
                function_name=func_name,
                function_signature=func_signature,
                start_line=start_line,
                end_line=end_line,
                caller_functions=caller_funcs,
                called_functions=called_funcs,
                contract_context=func_contract_context,
                ast_features=ast_features,
                metadata=metadata,
                label=func_label,
                slither_result=slither_result
            )
        
        except Exception as e:
            print(f"Error building context for function {getattr(function, 'name', 'unknown')}: {e}")
            return None
    
    def _build_function_context_regex(self,
                                     func_name: str,
                                     func_data: Dict,
                                     call_graph: Dict,
                                     contract_context: Dict,
                                     contract_file: str,
                                     contract_info: Optional[Dict]) -> Optional[FunctionContext]:
                           
        try:
                    
            callers = call_graph[func_name]['callers'][:3]
            callees = call_graph[func_name]['callees'][:3]
            
                           
            caller_funcs = []
            for caller_info in callers:
                caller_funcs.append({
                    'name': caller_info['name'],
                    'signature': caller_info.get('signature', caller_info['name']),
                    'code_snippet': f"// Caller: {caller_info['name']}"
                })
            
                           
            called_funcs = []
            for callee_info in callees:
                called_funcs.append({
                    'name': callee_info['name'],
                    'type': callee_info.get('type', 'unknown')
                })
            
                          
            ast_features = self._extract_ast_features_regex(func_data['code'])
            
                 
            metadata = {
                'contract_file': contract_file,
                'function_name': func_name,
                'visibility': func_data.get('visibility', 'unknown'),
                'state_mutability': func_data.get('state_mutability', 'unknown')
            }
            
            if contract_info:
                metadata.update(contract_info)
            
                    
            start_line = 1       
            end_line = 1         
            func_label = None
            
            if contract_info and contract_info.get('functions'):
                                                           
                for func_info in contract_info['functions']:
                    if func_info.get('name') == func_name:
                                
                        lines = func_info.get('lines', [])
                        if lines and len(lines) >= 2:
                            start_line = lines[0]
                            end_line = lines[1]
                        
                                             
                        if func_info.get('is_vulnerable'):
                            func_label = {
                                'is_vulnerable': True,
                                'vulnerability_types': [v['category'] for v in func_info.get('vulnerabilities', [])],
                                'vulnerability_details': func_info.get('vulnerabilities', []),
                                'source': 'ground_truth'
                            }
                        else:
                            func_label = {
                                'is_vulnerable': False,
                                'vulnerability_types': [],
                                'vulnerability_details': [],
                                'source': 'ground_truth'
                            }
                        break
            
            return FunctionContext(
                function_code=func_data['code'],
                function_name=func_name,
                function_signature=func_name,      
                start_line=start_line,
                end_line=end_line,
                caller_functions=caller_funcs,
                called_functions=called_funcs,
                contract_context=contract_context,
                ast_features=ast_features,
                metadata=metadata,
                label=func_label,
                slither_result={}
            )
        
        except Exception as e:
            print(f"Error building context for function {func_name}: {e}")
            return None
    
    def _extract_functions_regex(self, code: str) -> Dict[str, Dict]:
                      
        functions = {}
        
                
        pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|private|internal|external)?\s*(view|pure|payable)?\s*(returns\s*\([^)]*\))?\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        
        for match in re.finditer(pattern, code, re.DOTALL):
            func_name = match.group(1)
            visibility = match.group(2) or 'public'
            state_mutability = match.group(3) or 'nonpayable'
            func_body = match.group(5)
            
            functions[func_name] = {
                'code': match.group(0),
                'body': func_body,
                'visibility': visibility,
                'state_mutability': state_mutability
            }
        
        return functions
    
    def _extract_ast_features_slither(self, function) -> Dict:
                                
        try:
                        
            try:
                func_code = function.source_mapping.content if hasattr(function, 'source_mapping') and function.source_mapping else ""
            except:
                func_code = ""
            
                       
            try:
                nodes = function.nodes if hasattr(function, 'nodes') and function.nodes else []
            except:
                nodes = []
            
                                
            try:
                external_calls = function.external_calls_as_expressions if hasattr(function, 'external_calls_as_expressions') and function.external_calls_as_expressions else []
            except:
                external_calls = []
            
                                 
            try:
                state_vars_written = function.state_variables_written if hasattr(function, 'state_variables_written') and function.state_variables_written else []
                state_vars_read = function.state_variables_read if hasattr(function, 'state_variables_read') and function.state_variables_read else []
            except:
                state_vars_written = []
                state_vars_read = []
            
            features = {
                       
                'has_loops': bool(re.search(r'\b(for|while)\s*\(', func_code)),
                'has_if_statements': len(nodes) > 1,
                'complexity': len(nodes),
                
                       
                'has_external_calls': len(external_calls) > 0,
                'has_state_changes': len(state_vars_written) > 0,
                'reads_state_vars': len(state_vars_read) > 0,
                'writes_state_vars': len(state_vars_written) > 0,
                
                      
                'has_require': 'require(' in func_code,
                'uses_tx_origin': 'tx.origin' in func_code,
                'uses_delegatecall': 'delegatecall' in func_code,
                
                      
                'is_payable': function.payable if hasattr(function, 'payable') else False,
                'is_view': function.view if hasattr(function, 'view') else False,
                'is_pure': function.pure if hasattr(function, 'pure') else False,
                'visibility': str(function.visibility) if hasattr(function, 'visibility') else 'unknown'
            }
            
            return features
        
        except Exception as e:
                           
            return {
                'has_loops': False,
                'has_if_statements': False,
                'complexity': 0,
                'has_external_calls': False,
                'has_state_changes': False,
                'reads_state_vars': False,
                'writes_state_vars': False,
                'has_require': False,
                'uses_tx_origin': False,
                'uses_delegatecall': False,
                'is_payable': False,
                'is_view': False,
                'is_pure': False,
                'visibility': 'unknown'
            }
    
    def _extract_ast_features_regex(self, code: str) -> Dict:
                           
        features = {
                   
            'has_loops': bool(re.search(r'\b(for|while)\s*\(', code)),
            'has_if_statements': bool(re.search(r'\bif\s*\(', code)),
            'complexity': code.count('{'),        
            
                   
            'has_external_calls': bool(re.search(r'\.(call|delegatecall|staticcall)\(', code)),
            'has_state_changes': bool(re.search(r'[a-zA-Z_]\w*\s*=', code)),
            
                  
            'has_require': 'require(' in code,
            'uses_tx_origin': 'tx.origin' in code,
            'uses_delegatecall': 'delegatecall' in code,
            'uses_transfer': '.transfer(' in code,
            'uses_send': '.send(' in code,
            
                  
            'is_payable': 'payable' in code,
            'is_view': 'view' in code,
            'is_pure': 'pure' in code
        }
        
        return features
    
    def batch_process_contracts(self,
                               contract_files: List[str],
                               output_file: str,
                               contract_infos: Optional[Dict[str, Dict]] = None):
\
\
\
\
\
\
\
           
        all_function_contexts = []
        
        for contract_file in tqdm(contract_files, desc="Processing contracts"):
            contract_info = None
            if contract_infos:
                contract_info = contract_infos.get(contract_file)
            
            function_contexts = self.process_contract_to_functions(
                contract_file, contract_info
            )
            
            all_function_contexts.extend(function_contexts)
        
            
        self.save_function_contexts(all_function_contexts, output_file)
        
        print(f"\n✓ 共处理 {len(contract_files)} 个合约")
        print(f"✓ 生成 {len(all_function_contexts)} 个函数级样本")
        print(f"✓ 保存到: {output_file}")
    
    def save_function_contexts(self, 
                              function_contexts: List[FunctionContext],
                              output_file: str):
                          
        data = [asdict(fc) for fc in function_contexts]
        
                  
        data = data[:100]
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)


      
if __name__ == "__main__":
    processor = FunctionLevelProcessor(use_slither=True)
    
            
    function_contexts = processor.process_contract_to_functions(
        contract_file='path/to/contract.sol'
    )
    
    print(f"提取了 {len(function_contexts)} 个函数")
    
          
    contract_files = ['contract1.sol', 'contract2.sol']
    processor.batch_process_contracts(
        contract_files=contract_files,
        output_file='function_level_dataset.json'
    )