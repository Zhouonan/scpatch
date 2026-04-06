\
\
\
\
   

import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from openai import OpenAI
from src.tools.slice_builder import CodeSliceBuilder


@dataclass
class AnnotationConfig:
              
    api_key: str
    base_url: str = "https://api.openai.com/v1"                        
    model: str = "gpt-4o-mini"        
    temperature: float = 0.1            
    timeout: int = 60
    max_retries: int = 3
    retry_delay: int = 5
    verbose: bool = False                     
    use_json_mode: bool = True                                 


class LLMAnnotator:
\
\
\
\
\
\
       
    
    def __init__(self, config: AnnotationConfig):
\
\
\
\
\
           
        self.config = config
        self.client = OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=config.timeout
        )
        self.slice_builder = CodeSliceBuilder(include_comments=True)
        
              
        self.stats = {
            'total_requests': 0,
            'successful_annotations': 0,
            'failed_annotations': 0,
            'total_tokens_used': 0,
            'api_errors': 0
        }
    
    def annotate_function(self, func_data: Dict) -> Optional[Dict]:
\
\
\
\
\
\
\
\
           
                
        code_slice = self.slice_builder.build_simplified_contract(func_data)
        
                                    
        slither_result = func_data.get('slither_result', {})
        
                              
        return self._analyze_function(func_data, code_slice, slither_result)
    
    def _analyze_function(
        self,
        func_data: Dict,
        code_slice: str,
        slither_result: Dict
    ) -> Optional[Dict]:
\
\
\
\
\
\
\
           
                             
        if self.config.verbose:
            if func_data.get('label') and func_data.get('label').get('is_vulnerable'):
                print(f"   已标注为漏洞函数: {func_data.get('label').get('is_vulnerable')}")
            else:
                func_name = func_data.get('function_name', 'unknown')
                contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
                slither_says = 'vulnerable' if slither_result.get('is_vulnerable') else 'safe'
                print(f"\n📝 分析函数: {contract_name}.{func_name}")
                print(f"   Slither 判断: {slither_says}")
                if slither_result.get('vulnerability_details'):
                    vuln_types = [v.get('type') for v in slither_result['vulnerability_details']]
                    print(f"   Slither 发现: {', '.join(vuln_types)}")
                      
                   
        func_start_line = func_data.get('start_line', 1)
        
        prompt = self._build_prompt(
            code_slice=code_slice,
            slither_result=slither_result,
            label=func_data.get('label'),
            func_code=func_data.get('function_code', ''),          
            func_start_line=func_start_line            
        )
        
        if self.config.verbose:
            print("="*80)
            print("Prompt:")
            print("="*80)
            print(prompt)
            print("="*80)

                
        response = self._call_llm(prompt)
        if not response:
            return None
        
              
        return self._parse_response(response, slither_result)
    
    def _extract_vulnerable_code(self, func_code: str, line_numbers: List[int], func_start_line: int) -> str:
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
           
        if not func_code or not line_numbers:
            return ""
        
                 
        lines = func_code.split('\n')
        
                           
                                                    
        relative_line_numbers = []
        for line_num in line_numbers:
                                      
                                                            
            relative_line = line_num - func_start_line
            if 0 <= relative_line < len(lines):
                relative_line_numbers.append(relative_line)
        
        if not relative_line_numbers:
            return ""
        
                     
        min_line = min(relative_line_numbers)
        max_line = max(relative_line_numbers)
        
                    
        min_line = max(0, min_line)
        max_line = min(len(lines) - 1, max_line)
        
                            
        context_lines = 1  
        start_line = max(0, min_line - context_lines)
        end_line = min(len(lines) - 1, max_line + context_lines)
        
                     
        extracted_lines = []
        for i in range(start_line, end_line + 1):
            line_content = lines[i]
            original_line_num = func_start_line + i          
            
                   
            if i in relative_line_numbers:
                extracted_lines.append(f"// Line {original_line_num} (VULNERABLE): {line_content}")
            else:
                extracted_lines.append(f"// Line {original_line_num}: {line_content}")
        
        return "\n".join(extracted_lines)
    
    def _build_prompt(
        self,
        code_slice: str,
        slither_result: Dict,
        label: Dict,
        func_code: str = '',            
        func_start_line: int = 1              
    ) -> str:
                              
                                                   
        
        prompt = f"""Audit this Solidity function for exploitable vulnerabilities.

## Code to Analyze
```solidity
{code_slice}
```
"""
                                   
        if label and label.get('is_vulnerable'):
            prompt += f"""
## Ground Truth Label:
This function is labeled as {label['is_vulnerable']}, with vulnerability types: {label['vulnerability_types']}.
"""
            
                               
            if label.get('is_vulnerable') and label.get('vulnerability_details'):
                vuln_details = label['vulnerability_details']
                if vuln_details and len(vuln_details) > 0:
                    prompt += "\n### Vulnerable Code Details:\n"
                    
                            
                    for i, vuln in enumerate(vuln_details):
                        line_numbers = vuln.get('lines', [])
                        category = vuln.get('category', 'unknown')
                        
                        if line_numbers and func_code:
                                          
                            vulnerable_code = self._extract_vulnerable_code(
                                func_code, 
                                line_numbers, 
                                func_start_line
                            )
                            prompt += f"""
**Vulnerability {i+1}** (Category: {category}):
Lines: {line_numbers}

```solidity
{vulnerable_code}
```
"""
                        elif line_numbers:
                                             
                            prompt += f"""
**Vulnerability {i+1}** (Category: {category}):
Lines: {line_numbers}
"""
        
                          
        if slither_result:
            has_findings = slither_result.get('is_vulnerable', False)
            details = slither_result.get('vulnerability_details', [])
            
            prompt += "\n## Slither Analysis (Reference)\n"
            
            if has_findings and details:
                slither_summary = self._build_slither_summary(details)
                prompt += f"""Slither found these issues:
{slither_summary}

Note: Slither can have false positives. Verify each issue independently.
"""
            else:
                prompt += "Slither found no critical vulnerabilities. But check carefully - it can miss issues.\n"
        
        prompt += """
## Your Task
1. Analyze for EXPLOITABLE vulnerabilities (not just best practices)
2. Consider Slither's input but make your own judgment
3. Describe concrete attack scenarios for any vulnerabilities found
4. Return analysis in JSON format as specified in your system instructions

Focus on what can actually be exploited to cause real harm."""
        
        return prompt
    
    def _get_system_prompt(self) -> str:
                                     
        return """You are an expert Solidity security auditor. Your role is to identify EXPLOITABLE vulnerabilities in smart contracts.

## Core Principles
1. Focus on EXPLOITABILITY - only real attack vectors count as vulnerabilities
2. Distinguish: Critical bugs vs Best practices vs Code quality
3. Consider Solidity version context (0.4.x has different syntax/features)
4. Be precise - describe concrete attack scenarios

## Output Format (JSON)
```json
{
  "is_safe": <boolean>,
  "analysis": "<professional paragraph>",
  "reasoning": "<detailed technical explanation>",
  "vulnerability_types": ["<actual exploits only>"],
  "severity": <0-10, see scale below>,
  "confidence": <0-1>,
  "agrees_with_slither": <boolean>,
  "slither_critique": "<if disagree, explain why>",
  "suggested_fix": "<how to fix vulnerabilities>"
}
```

## Severity Scale
- 9-10: Critical - Direct fund theft/contract destruction
- 7-8: High - Significant impact, specific conditions needed
- 5-6: Medium - Exploitable but limited impact
- 3-4: Low - Theoretical risk, unlikely conditions
- 1-2: Info - Best practice issue, not exploitable
- 0: Safe - No vulnerabilities or only code quality issues

## What IS Vulnerable
  Reentrancy enabling fund theft
  Access control bypass
  Actual overflow causing financial loss
  Delegatecall to user-controlled address

## What is NOT Vulnerable
  Missing `require(to != address(0))` - bad practice, rarely exploitable
  Function name constructor in 0.4.x - correct syntax, not a bug
  No SafeMath in 0.4.x - only if actually exploitable
  Missing events - code quality issue

## Writing Style
- Use professional, flowing paragraphs (not bullet points)
- Write like a security audit report
- Be concise but thorough
- Cite specific code when explaining issues"""
    
    def _build_slither_summary(self, vulnerability_details: List[Dict]) -> str:
                           
        if not vulnerability_details:
            return "No vulnerabilities detected by Slither."
        
        summary_lines = []
        for i, vuln in enumerate(vulnerability_details, 1):
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Unknown')
            description = vuln.get('description', 'No description')
            
            summary_lines.append(f"{i}. **{vuln_type}** (Severity: {severity})")
            summary_lines.append(f"   {description}")
        
        return "\n".join(summary_lines)
        
    def _select_target_vulnerability(self, vulnerability_details: List[Dict]) -> Dict:
                          
        severity_order = {
            'High': 4,
            'Medium': 3,
            'Low': 2,
            'Informational': 1,
            'Optimization': 0
        }
        
        sorted_vulns = sorted(
            vulnerability_details,
            key=lambda v: severity_order.get(v.get('severity', 'Low'), 2),
            reverse=True
        )
        
        return sorted_vulns[0] if sorted_vulns else {}
    
    def _call_llm(self, prompt: str) -> Optional[str]:
\
\
\
\
\
\
\
\
           
        self.stats['total_requests'] += 1
        
        for attempt in range(self.config.max_retries):
            try:
                                          
                system_prompt = self._get_system_prompt()
                
                         
                api_params = {
                    'model': self.config.model,
                    'messages': [
                        {
                            "role": "system",
                            "content": system_prompt
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    'temperature': self.config.temperature,
                }
                
                                                
                if self.config.use_json_mode:
                    api_params['response_format'] = {'type': 'json_object'}
                
                response = self.client.chat.completions.create(**api_params)
                
                           
                if hasattr(response, 'usage') and response.usage:
                    self.stats['total_tokens_used'] += response.usage.total_tokens
                
                content = response.choices[0].message.content
                
                                   
                if self.config.verbose:
                    print("\n" + "="*80)
                    print("🤖 LLM 响应:")
                    print("="*80)
                    print(content)
                    print("="*80 + "\n")
                
                return content
                
            except Exception as e:
                self.stats['api_errors'] += 1
                error_msg = str(e).lower()
                
                                   
                if self.config.use_json_mode and ('json' in error_msg or 'response_format' in error_msg):
                    print(f"⚠️  模型不支持JSON模式，自动切换到普通模式")
                    self.config.use_json_mode = False
                                  
                    continue
                
                print(f"LLM API调用失败 (尝试 {attempt + 1}/{self.config.max_retries}): {e}")
                
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    print(f"达到最大重试次数，放弃调用")
                    return None
        
        return None
    
    def _parse_response(
        self,
        response: str,
        slither_result: Dict
    ) -> Optional[Dict]:
                            
        try:
                     
            json_str = self._extract_json_from_response(response)
            if not json_str:
                print(f"无法从响应中提取JSON: {response[:200]}")
                return None
            
            data = json.loads(json_str)
            
                        
            analysis = data.get('analysis', '')
            if isinstance(analysis, list):
                analysis = '\n'.join(str(item) for item in analysis)
            
            reasoning = data.get('reasoning', '')
            if isinstance(reasoning, list):
                reasoning = '\n'.join(str(item) for item in reasoning)
            
            suggested_fix = data.get('suggested_fix', '')
            if isinstance(suggested_fix, list):
                suggested_fix = '\n'.join(str(item) for item in suggested_fix)
            
            slither_critique = data.get('slither_critique', '')
            if isinstance(slither_critique, list):
                slither_critique = '\n'.join(str(item) for item in slither_critique)
            
                               
            is_safe = data.get('is_safe', True)
            label = 'safe' if is_safe else 'vulnerable'
            
                            
            agrees_with_slither = data.get('agrees_with_slither', True)
            slither_says_vulnerable = slither_result.get('is_vulnerable', False) if slither_result else False
            
                    
            annotation = {
                'label': label,
                'analysis': analysis,
                'reasoning': reasoning,
                'vulnerability_types': data.get('vulnerability_types', []),
                'severity': float(data.get('severity', 0.0)),
                'confidence': float(data.get('confidence', 0.5)),
                'suggested_fix': suggested_fix,
                'slither_agreement': agrees_with_slither,
                'slither_critique': slither_critique,
                'metadata': {
                    'model': self.config.model,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'slither_result': 'vulnerable' if slither_says_vulnerable else 'safe',
                    'llm_result': label,
                    'agreement': agrees_with_slither
                }
            }
            
                                         
            if slither_result:
                if slither_says_vulnerable != (not is_safe):
                    annotation['metadata']['disagreement'] = {
                        'slither': 'vulnerable' if slither_says_vulnerable else 'safe',
                        'llm': label,
                        'critique': slither_critique
                    }
            
            self.stats['successful_annotations'] += 1
            
                              
            if self.config.verbose:
                print(f"\n✅ 解析结果:")
                print(f"   LLM 判断: {annotation['label']}")
                print(f"   置信度: {annotation['confidence']:.2f}")
                if annotation['vulnerability_types']:
                    print(f"   漏洞类型: {', '.join(annotation['vulnerability_types'])}")
                if annotation['severity'] > 0:
                    print(f"   严重程度: {annotation['severity']:.1f}/10")
                print(f"   同意Slither: {'是' if annotation['slither_agreement'] else '否'}")
                if 'disagreement' in annotation['metadata']:
                    print(f"   ⚠️  意见分歧: Slither说{annotation['metadata']['disagreement']['slither']}, LLM说{annotation['metadata']['disagreement']['llm']}")
                    if annotation['slither_critique']:
                        print(f"   分歧原因: {annotation['slither_critique'][:150]}...")
            
            return annotation
            
        except json.JSONDecodeError as e:
            print(f"JSON解析失败: {e}")
            print(f"响应内容: {response[:500]}")
            self.stats['failed_annotations'] += 1
            return None
        except Exception as e:
            print(f"解析响应时出错: {e}")
            self.stats['failed_annotations'] += 1
            return None
    
    def _parse_vulnerable_response(
        self, 
        response: str, 
        slither_result: Dict
    ) -> Optional[Dict]:
                           
        try:
                      
            json_str = self._extract_json_from_response(response)
            if not json_str:
                print(f"无法从响应中提取JSON: {response[:200]}")
                return None
            
            data = json.loads(json_str)
            
                        
            analysis = data.get('analysis', '')
            if isinstance(analysis, list):
                analysis = '\n'.join(str(item) for item in analysis)
            
            reasoning = data.get('reasoning', '')
            if isinstance(reasoning, list):
                reasoning = '\n'.join(str(item) for item in reasoning)
            
            suggested_fix = data.get('suggested_fix_for_others', '')
            if isinstance(suggested_fix, list):
                suggested_fix = '\n'.join(str(item) for item in suggested_fix)
            
                    
            annotation = {
                'label': 'vulnerable',
                'analysis': analysis,
                'reasoning': reasoning,
                'vulnerability_types': data.get('vulnerability_types', []),
                'severity': float(data.get('severity', 5.0)),
                'confidence': float(data.get('confidence', 0.5)),
                'suggested_fix': suggested_fix,
                'metadata': {
                    'model': self.config.model,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'slither_version': slither_result.get('version', 'unknown')
                }
            }
            
            self.stats['successful_annotations'] += 1
            return annotation
            
        except json.JSONDecodeError as e:
            print(f"JSON解析失败: {e}")
            print(f"响应内容: {response[:500]}")
            self.stats['failed_annotations'] += 1
            return None
        except Exception as e:
            print(f"解析响应时出错: {e}")
            self.stats['failed_annotations'] += 1
            return None
    
    def _parse_safe_response(self, response: str) -> Optional[Dict]:
                          
        try:
                      
            json_str = self._extract_json_from_response(response)
            if not json_str:
                print(f"无法从响应中提取JSON: {response[:200]}")
                return None
            
            data = json.loads(json_str)
            
                                        
            reasoning = data.get('safety_reasoning', '')
            if isinstance(reasoning, list):
                reasoning = '\n'.join(str(item) for item in reasoning)
            
                                       
            analysis = data.get('analysis', '')
            if isinstance(analysis, list):
                analysis = '\n'.join(str(item) for item in analysis)
            
                                             
            best_practices = data.get('best_practices', '')
            if isinstance(best_practices, list):
                best_practices = '\n'.join(str(item) for item in best_practices)
            
                    
            annotation = {
                'label': 'safe',
                'analysis': analysis,
                'reasoning': reasoning,
                'vulnerability_types': [],
                'severity': 0.0,
                'confidence': float(data.get('confidence', 0.5)),
                'best_practices': best_practices,
                'metadata': {
                    'model': self.config.model,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            
            self.stats['successful_annotations'] += 1
            return annotation
            
        except json.JSONDecodeError as e:
            print(f"JSON解析失败: {e}")
            print(f"响应内容: {response[:500]}")
            self.stats['failed_annotations'] += 1
            return None
        except Exception as e:
            print(f"解析响应时出错: {e}")
            self.stats['failed_annotations'] += 1
            return None
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
                              
        import re
        
                                       
        response_stripped = response.strip()
        if response_stripped.startswith('{') and response_stripped.endswith('}'):
            return response_stripped
        
                             
        json_code_block = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_code_block:
            return json_code_block.group(1)
        
                         
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
        if json_match:
            return json_match.group(0)
        
        return None
    
    def batch_annotate(
        self, 
        functions_data: List[Dict],
        progress_callback=None
    ) -> List[Tuple[Dict, Optional[Dict]]]:
\
\
\
\
\
\
\
\
\
           
        results = []
        total = len(functions_data)
        
        print(f"开始批量标注，共 {total} 个函数...")
        
        for i, func_data in enumerate(functions_data, 1):
            if progress_callback:
                progress_callback(i, total)
            
            print(f"[{i}/{total}] 标注函数: {func_data.get('function_name', 'unknown')}...")
            
            annotation = self.annotate_function(func_data)
            results.append((func_data, annotation))
            
                          
            if i < total:
                time.sleep(0.5)
        
        print(f"\n标注完成！")
        self.print_stats()
        
        return results
    
    def print_stats(self):
                    
        print("\n" + "="*60)
        print("标注统计信息:")
        print(f"  总请求数: {self.stats['total_requests']}")
        print(f"  成功标注: {self.stats['successful_annotations']}")
        print(f"  失败标注: {self.stats['failed_annotations']}")
        print(f"  API错误: {self.stats['api_errors']}")
        print(f"  总Token使用: {self.stats['total_tokens_used']}")
        if self.stats['successful_annotations'] > 0:
            avg_tokens = self.stats['total_tokens_used'] / self.stats['successful_annotations']
            print(f"  平均Token/次: {avg_tokens:.1f}")
        print("="*60)


if __name__ == "__main__":
          
    import os
    
        
    config = AnnotationConfig(
        api_key=os.getenv("OPENAI_API_KEY", "your-api-key"),
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        model="gpt-4o-mini",
        temperature=0.1
    )
    
           
    annotator = LLMAnnotator(config)
    
          
    mock_vulnerable_func = {
        "function_name": "withdraw",
        "function_code": "function withdraw(uint amount) public {\n    msg.sender.call{value: amount}(\"\");\n    balances[msg.sender] -= amount;\n}",
        "contract_context": {
            "contract_name": "Vault",
            "state_variables": [
                {"code": "mapping(address => uint) public balances;"}
            ],
            "modifiers": []
        },
        "called_functions": [],
        "slither_result": {
            "is_vulnerable": True,
            "vulnerability_details": [
                {
                    "type": "reentrancy-eth",
                    "severity": "High",
                    "description": "Reentrancy in withdraw function. External call before state update.",
                    "start_line": 10,
                    "end_line": 15,
                    "lines": [10, 11, 12, 13, 14, 15]
                }
            ]
        }
    }
    
    print("测试标注器...")
    result = annotator.annotate_function(mock_vulnerable_func)
    
    if result:
        print("\n标注结果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("标注失败")

