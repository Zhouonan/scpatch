\
\
\
\
   

import json
from typing import Dict, List, Optional, Any
from src.tools.slice_builder import CodeSliceBuilder

class PromptFormatter:
    def __init__(self, include_comments: bool = True):
        self.slice_builder = CodeSliceBuilder(include_comments=include_comments)
    
    def format_instruction(self) -> str:
                     
        instruction = (
            "Analyze the provided Solidity function code for security vulnerabilities. "
            "If the code is safe, output 'Safe' with a brief analysis. "
            "If vulnerabilities are detected, provide detailed information including: "
            "vulnerability type, severity score (0-10), reasoning, and location."
        )
        return instruction

    def format_input(self, func_data: Dict) -> str:
\
\
\
           
        return self.slice_builder.build_slice(func_data)

    def format_output(self, func_data: Dict) -> str:
                                  
        labels = func_data.get('slither_result') or {}
        
                 
        is_vulnerable = labels.get('is_vulnerable', False)
        
        if not is_vulnerable:
                          
            return self.format_safe_output(func_data, labels)
        else:
                                
            return self.format_vulnerable_output(func_data, labels)
    
    def format_safe_output(self, func_data: Dict, labels: Dict) -> str:
                        
        analysis = labels.get('analysis', '')
        
        if not analysis:
            analysis = "No obvious security vulnerabilities detected in the function."
        
        output = f"Analysis: {analysis}\nResult: Safe"
        return output
    
    def format_vulnerable_output(self, func_data: Dict, labels: Dict) -> str:
                                 
                                            
        vuln_details = labels.get('vulnerability_details', [])
        
        if vuln_details:
                            
            main_vuln = self.select_most_severe_vulnerability(vuln_details)
            
                    
            vuln_type = main_vuln.get('type', 'Unknown')
            
                                         
            reasoning = main_vuln.get('description', '').strip()
            if not reasoning:
                reasoning = self.generate_default_reasoning(vuln_type, func_data)
            
                                       
            severity_str = main_vuln.get('severity', 'Medium')
            severity = self.convert_severity_to_score(severity_str, vuln_type)
            
                                       
            location = self.extract_location_from_description(reasoning)
            
        else:
                         
            vuln_types = self.extract_vulnerability_types(labels)
            vuln_type = vuln_types[0] if vuln_types else "Unknown"
            reasoning = labels.get('reasoning', '') or self.generate_default_reasoning(vuln_type, func_data)
            severity = labels.get('severity', self.estimate_severity(vuln_type))
            location = labels.get('location', 'Function body')
        
                               
        if len(vuln_details) > 1:
            other_types = [v.get('type') for v in vuln_details if v.get('type') != vuln_type]
            if other_types:
                reasoning = f"{reasoning}\nNote: This function also contains other issues: {', '.join(set(other_types))}."
        
                  
        output_data = {
            "reasoning": reasoning,
            "type": vuln_type,
            "severity": severity,
            "location": location
        }
        
        return json.dumps(output_data, indent=2, ensure_ascii=False)
    
    def select_most_severe_vulnerability(self, vuln_details: List[Dict]) -> Dict:
                                  
                             
        severity_order = {
            'High': 4,
            'Medium': 3,
            'Low': 2,
            'Informational': 1,
            'Optimization': 0
        }
        
                        
        sorted_vulns = sorted(
            vuln_details,
            key=lambda v: severity_order.get(v.get('severity', 'Low'), 2),
            reverse=True
        )
        
        return sorted_vulns[0] if sorted_vulns else {}
    
    def convert_severity_to_score(self, severity_str: str, vuln_type: str) -> int:
                                           
              
        severity_mapping = {
            'High': 9,
            'Medium': 6,
            'Low': 3,
            'Informational': 1,
            'Optimization': 1
        }
        
        base_score = severity_mapping.get(severity_str, 5)
        
                    
        type_adjustments = {
            'reentrancy': +1,         
            'delegatecall': +1,
            'access_control': +1,
            'arithmetic': 0,
            'unchecked_call': 0,
            'gas_optimization': -2,             
            'code_quality': -2,
        }
        
        vuln_type_lower = vuln_type.lower().replace(' ', '_').replace('-', '_')
        adjustment = 0
        for key, adj in type_adjustments.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                adjustment = adj
                break
        
                    
        final_score = max(0, min(10, base_score + adjustment))
        return final_score
    
    def extract_location_from_description(self, description: str) -> str:
                                 
                               
        import re
        
                                            
        line_pattern = r'\.sol[:#](\d+)(?:-(\d+))?'
        matches = re.findall(line_pattern, description)
        
        if matches:
                       
            start_line = matches[0][0]
            end_line = matches[0][1] if matches[0][1] else start_line
            if start_line == end_line:
                return f"Line {start_line}"
            else:
                return f"Lines {start_line}-{end_line}"
        
                          
        return "Function body"
    
    def extract_vulnerability_types(self, labels: Dict) -> List[str]:
                              
        vuln_types = []
        
                                  
        if labels.get('vulnerability_types'):
            vuln_types = labels['vulnerability_types']
                                    
        elif labels.get('vulnerability_details'):
            vuln_types = [
                detail.get('type')
                for detail in labels['vulnerability_details']
                if detail.get('type')
            ]
                                   
        elif labels.get('vulnerability_type'):
            vuln_types = [labels['vulnerability_type']]
        
               
        return sorted(list(set([v for v in vuln_types if v])))
    
    def generate_default_reasoning(self, vuln_type: str, func_data: Dict) -> str:
                          
        reasoning_templates = {
            'reentrancy': 'The function performs external calls before updating state variables, which may allow reentrancy attacks.',
            'access_control': 'The function lacks proper access control checks, allowing unauthorized users to execute sensitive operations.',
            'arithmetic': 'The function contains arithmetic operations that may overflow or underflow.',
            'unchecked_call': 'The function makes external calls without checking the return value.',
            'delegatecall': 'The function uses delegatecall which may lead to unintended code execution.',
            'tx_origin': 'The function uses tx.origin for authorization, which is vulnerable to phishing attacks.',
            'timestamp_dependence': 'The function relies on block.timestamp which can be manipulated by miners.',
            'uninitialized_storage': 'The function uses uninitialized storage variables.',
        }
        
                   
        vuln_type_lower = vuln_type.lower().replace(' ', '_').replace('-', '_')
        
                 
        for key, template in reasoning_templates.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                return template
        
        return f"The function contains a {vuln_type} vulnerability."
    
    def estimate_severity(self, vuln_type: str) -> int:
                            
        severity_map = {
            'reentrancy': 9,
            'access_control': 8,
            'delegatecall': 9,
            'arithmetic': 7,
            'unchecked_call': 6,
            'tx_origin': 7,
            'timestamp_dependence': 5,
            'uninitialized_storage': 8,
            'dos': 6,
            'front_running': 6,
        }
        
        vuln_type_lower = vuln_type.lower().replace(' ', '_').replace('-', '_')
        
        for key, severity in severity_map.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                return severity
        
        return 5            
    
                                      

                                                       
                                                           
                                                                 
                                                                                                                     
                                                                                       
                                                   

    def format_fix_instruction(self) -> str:
                                                                
                                                                                                             
                
                                                         
                                              

                    
                                                                                           
     
              
             
                                    
                   
    
     
        prompt = f"""You are an expert Solidity smart contract security auditor. 
Your task is to fix security vulnerabilities in Solidity code while maintaining functionality. 
Provide the complete fixed function code.
"""
        return prompt

    def format_fix_input_for_our_models(self, pair: Dict[str, Any]) -> str:
\
\
\
\
\
\
           
        meta_lines = []
        
                                   
        vuln_types = pair.get("vulnerability_types")
        if vuln_types:
            if isinstance(vuln_types, list):
                types = ", ".join(vuln_types)
            else:
                types = str(vuln_types)
            meta_lines.append(f"- Type: {types}")
            
                         
        if pair.get("severity") is not None:
            meta_lines.append(f"- Severity: {pair['severity']}")
            
                                    
        input_text = ""
        if meta_lines:
            input_text += "### Vulnerability Info\n" + "\n".join(meta_lines) + "\n\n"
            
                                                            
        code = pair.get('vulnerable_code') or pair.get('function_code') or pair.get('code_slice') or ''
        input_text += f"### Source Code\n{code}"
        
        return input_text

                                                                              
    
    def format_general_fix_prompt(self, code_slice: str, annotation: Dict, solc_version: str) -> str:
\
\
\
           
        vulnerability_types = annotation.get('vulnerability_types', [])
        analysis = annotation.get('analysis', '')
        severity = annotation.get('severity', 0)
        
        prompt = f"""You are an expert Solidity security engineer. Your task is to fix the vulnerabilities in the following smart contract function.

**Original Vulnerable Code:**
```solidity
{code_slice}
```

**Security Analysis:**
{analysis}

**Identified Vulnerabilities:**
{', '.join(vulnerability_types)}

**Severity Score:** {severity}/10

**Your Task:**
Generate a FIXED version of this function that:
1. **Eliminates all identified vulnerabilities**
2. **Maintains the original functionality** (same inputs/outputs, same business logic)
3. **Follows Solidity best practices**
4. **Is syntactically correct** and will compile
5. **Uses appropriate Solidity version features, currently using Solidity {solc_version}**
"""
        return prompt

    def format_general_fix_prompt_rich(self, code_slice: str, annotation: Dict, solc_version: str) -> str:
\
\
\
\
\
\
\
\
\
           
        vulnerability_types = annotation.get('vulnerability_types', [])
        analysis = annotation.get('analysis', '')
        severity = annotation.get('severity', 0)

                                                            
        vulnerable_code_details = annotation.get("vulnerable_code_details") or ""
        slither_section = annotation.get("slither_section") or ""

        prompt = f"""You are an expert Solidity security engineer. Your task is to fix the vulnerabilities in the following smart contract function.

**Original Vulnerable Code:**
```solidity
{code_slice}
```

## Ground Truth (Reference)
This function is labeled as vulnerable, with vulnerability types: {', '.join(vulnerability_types)}.

{vulnerable_code_details}

{slither_section}

## Security Context
{analysis}

## Your Task
Generate a FIXED version of this function that:
1. **Eliminates all identified vulnerabilities**
2. **Maintains the original functionality** (same inputs/outputs, same business logic)
3. **Follows Solidity best practices**
4. **Is syntactically correct** and will compile
5. **Uses appropriate Solidity version features, currently using Solidity {solc_version}**
"""
        return prompt

    def format_general_system_prompt(self) -> str:
                                                      
        return """You are an expert Solidity security engineer specializing in vulnerability remediation.
**CRITICAL Requirements:**
1. Return ONLY the fixed function code (NOT the entire contract)
2. Preserve the function signature (name, parameters, return types, visibility)
3. Keep the same state variable interactions whenever possible
4. Ensure the code is complete and will compile
5. Add brief security comments explaining key fixes

**Required Output (JSON format):**
{{
  "fixed_code": "The complete fixed function code in Solidity",
  "fix_analysis": "A clear paragraph explaining what vulnerabilities were fixed and how. Describe the specific changes made and why they improve security.",
  "key_changes": ["list", "of", "main", "security", "improvements"],
  "solidity_version_notes": "Any version-specific considerations (e.g., SafeMath vs built-in checks)"
}}    
"""

    def format_retry_prompt(self, previous_fixed_code: str, error_summary: str, vulnerability_types: List[str], solc_version: str) -> str:
                                                                      
        prompt = f"""You are an expert Solidity security engineer. Your previous fix attempt failed to compile.

**Solidity Version: {solc_version}**

**Previous Fix Attempt (Function Code):**
```solidity
{previous_fixed_code}
```

**Compilation Error:**
```
{error_summary}
```

**Vulnerabilities to Fix:**
{', '.join(vulnerability_types)}

**Your Task:**
Fix the compilation error in the function above while still addressing all vulnerabilities.

**Output Format:**
Return ONLY the corrected Solidity function code in a code block.

**Example:**
```solidity
function fixedFunction() public {{
    // Fixed code
}}
```"""
        return prompt

    def format_retry_system_prompt(self) -> str:
                                                        
        return """You are an expert Solidity security engineer specializing in fixing compilation errors.
**CRITICAL Requirements for Retry:**
1. Return ONLY the fixed function code (NOT the entire contract)
2. Preserve ALL security fixes from the previous attempt
3. Fix ONLY the compilation errors while keeping everything else unchanged
4. Ensure the code is complete and will compile
5. Do NOT add any explanations, JSON, or other text - just the code

**Required Output for Retry:**
```solidity
// The complete fixed function code ONLY
function functionName(...) ... {
    // Fixed code here
}
```"""

    def format_fix_prompt_for_our_models(self, code_slice: str, annotation: Dict, solc_version: str, function_name: str, include_instruction: bool = False) -> str:
\
\
\
\
\
\
\
\
           
                                                                                          
                                                                   
        annotation = annotation or {}
        vulnerability_types = annotation.get('vulnerability_types', [])
        severity = annotation.get('severity', 0)
        
                        
        meta_lines = []
        
                         
        if vulnerability_types:
            if isinstance(vulnerability_types, list):
                types = ", ".join(vulnerability_types)
            else:
                types = str(vulnerability_types)
            meta_lines.append(f"- Type: {types}")
        
                         
        if severity is not None:
            meta_lines.append(f"- Severity: {severity}")
        
                          
        input_text = f"The following Solidity function has been identified with security vulnerabilities: \n\n"
        input_text += f"**Function:** {function_name}\n\n"
        if meta_lines:
            input_text += "**Vulnerability Info:**\n" + "\n".join(meta_lines) + "\n\n"
        
        input_text += f"**Source Code:**\n{code_slice}"

        input_text += f"Please provide the complete fixed version of this code that addresses the identified vulnerabilities. \nOutput ONLY the corrected Solidity function code in a code block not the entire contract."
        if include_instruction:
                              
            instruction = self.format_fix_instruction()
                                                   
            full_prompt = f"{instruction}\n\n{input_text}"
            return full_prompt
        else:
            return input_text
