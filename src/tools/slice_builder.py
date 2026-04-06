\
\
\
\
\
\
   

from typing import Dict, List, Optional, Union
import re

class CodeSliceBuilder:
    def __init__(self, include_comments: bool = False):
\
\
\
           
        self.include_comments = include_comments

    def build_slice(self, func_context: Dict) -> str:
\
\
\
\
\
\
\
\
           
        parts = []

        def _get_code(item: object) -> str:
                                                                                             
            if isinstance(item, dict):
                return str(item.get('code', '') or '')
            if isinstance(item, str):
                return item
            return ""

        def _maybe_comment_modifier(code: str) -> str:
\
\
\
               
            s = (code or "").strip()
            if not s:
                return ""
                                                                                
            if "modifier " in s or "{" in s or "}" in s or "(" in s or ")" in s or "\n" in s:
                return code
                                        
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
                return f"// modifier: {s}"
            return code
        
                        
        contract_name = func_context.get('contract_context', {}).get('contract_name', 'Unknown')
        func_name = func_context.get('function_name', 'Unknown')
        
        if self.include_comments:
            parts.append(f"// Context: Contract {contract_name}, Function {func_name}")
            parts.append("")

                                             
                   
        state_vars = func_context.get('contract_context', {}).get('state_variables', [])
        if state_vars:
            if self.include_comments:
                parts.append("// --- State Variables ---")
            
            for var in state_vars:
                code = _get_code(var)
                if not code and isinstance(var, dict):
                                                         
                    code = f"{var.get('type', 'uint')} {var.get('visibility', 'internal')} {var.get('name', 'var')};"
                if code:
                    parts.append(code)
            parts.append("")

                                 
        structures = func_context.get('contract_context', {}).get('structures', [])
        if structures:
            if self.include_comments:
                parts.append("// --- Structures ---")
            
            for struct in structures:
                code = _get_code(struct)
                if code:
                    parts.append(code)
            parts.append("")

                                
                                                     
        modifiers = func_context.get('contract_context', {}).get('modifiers', [])
        if modifiers:
            if self.include_comments:
                parts.append("// --- Modifiers ---")
            
            for mod in modifiers:
                code = _maybe_comment_modifier(_get_code(mod))
                            
                if code:
                    parts.append(code)
            parts.append("")

                                                 
        callees = func_context.get('called_functions', [])
        if callees:
            if self.include_comments:
                parts.append("// --- Helper Functions (Callees) ---")
            
            for callee in callees:
                code = _get_code(callee)
                if code:
                    parts.append(code)
            parts.append("")

                            
        if self.include_comments:
            parts.append("// --- Target Function ---")
        
        func_code = func_context.get('function_code', '')
        if func_code:
            parts.append(func_code)
        
        return "\n".join(parts)

    def build_simplified_contract(
        self,
        func_context: Dict,
        fixed_code: Optional[str] = None
    ) -> str:
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
           
        contract_context = func_context.get('contract_context', {})
        contract_name = contract_context.get('contract_name', 'TestContract')

        def _get_code(item: object) -> str:
                                                                                             
            if isinstance(item, dict):
                return str(item.get('code', '') or '')
            if isinstance(item, str):
                return item
            return ""

        def _sanitize_modifier_code(code: str) -> str:
\
\
\
               
            s = (code or "").strip()
            if not s:
                return ""
            if "modifier " in s or "{" in s or "}" in s:
                return code
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
                return f"// modifier: {s}"
            return code
        
                      
        solidity_version = func_context.get('solidity_version', '0.8.0')
        
                
        full_contract = f"// SPDX-License-Identifier: MIT\n"
        full_contract += f"pragma solidity ^{solidity_version};\n\n"
        
        full_contract += f"contract {contract_name} {{\n"
        
                
        state_vars = contract_context.get('state_variables', [])
        if state_vars:
            full_contract += "    // State variables\n"
            for var in state_vars:
                var_code = _get_code(var)
                if var_code and not var_code.strip().startswith('//'):
                    clean_code = var_code.strip()
                    if not clean_code.endswith(';'):
                        clean_code += ';'
                    full_contract += "    " + clean_code + "\n"
            full_contract += "\n"
        
               
        structures = contract_context.get('structures', [])
        if structures:
            full_contract += "    // Structures\n"
            for struct in structures:
                struct_code = _get_code(struct)
                if struct_code:
                              
                    for line in struct_code.split('\n'):
                        full_contract += "    " + line + "\n"
                    full_contract += "\n"

               
        modifiers = contract_context.get('modifiers', [])
        if modifiers:
            full_contract += "    // Modifiers\n"
            for mod in modifiers:
                mod_code = _sanitize_modifier_code(_get_code(mod))
                if mod_code:
                              
                    for line in mod_code.split('\n'):
                        full_contract += "    " + line + "\n"
                    full_contract += "\n"
        
                             
                                                            
                     
                                                          
                                    
                                                 
                                 
                                 
                                                          
                                                               
                                           
        
                          
        target_code = fixed_code if fixed_code is not None else func_context.get('function_code', '')
        if target_code:
            full_contract += "    // Target function\n"
            for line in target_code.split('\n'):
                full_contract += "    " + line + "\n"
        
        full_contract += "}\n"
        return full_contract

    def build_with_mode(
        self,
        func_context: Dict,
        mode: str = "slice",
        fixed_code: Optional[str] = None
    ) -> str:
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
           
        if mode == "contract":
            return self.build_simplified_contract(func_context, fixed_code)
        else:
            return self.build_slice(func_context)

    def rebuild_full_contract(
        self,
        func_data: Dict,
        fixed_code: str
    ) -> Optional[str]:
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
           
        import os
        
        full_contract: Optional[str] = None

                             
        original_path = func_data.get('contract_path') or func_data.get('metadata', {}).get('contract_file')
        original_func_code = func_data.get('function_code', '')
        
                      
        original_path = os.path.join(os.getcwd(), original_path)
        
        if original_path and os.path.exists(original_path):
            try:
                       
                with open(original_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                original_source = "".join(lines)

                           
                extra_defs_insert = ""
                extra_definitions = func_data.get('llm_extra_definitions', [])
                if extra_definitions:
                    extra_defs_insert = "\n    // LLM Extra Definitions\n"
                    for def_code in extra_definitions:
                        extra_defs_insert += f"    {def_code}\n"
                    extra_defs_insert += "\n"

                                    
                start_line = func_data.get('start_line')
                end_line = func_data.get('end_line')
                
                                                
                if (start_line is not None and end_line is not None and 
                    start_line > 0 and end_line <= len(lines) and 
                    start_line < end_line):
                    
                    if self.include_comments:                           
                        print(f"   Using line-based replacement: {start_line}-{end_line}")

                             
                    new_content_parts = []
                    
                                              
                    new_content_parts.append("".join(lines[:start_line-1]))
                    
                                     
                    if extra_defs_insert:
                        new_content_parts.append(extra_defs_insert)
                    
                                 
                                                  
                    first_line = lines[start_line-1]
                    indent = ""
                    for char in first_line:
                        if char.isspace():
                            indent += char
                        else:
                            break
                    
                                                    
                                                      
                                              
                    new_content_parts.append(fixed_code)
                    
                                                         
                    if not fixed_code.endswith('\n'):
                        new_content_parts.append('\n')
                    
                                           
                    new_content_parts.append("".join(lines[end_line:]))
                    
                    full_contract = "".join(new_content_parts)
                    return full_contract

                                  
                if original_func_code and original_func_code in original_source:
                            
                    replacement = fixed_code
                    if extra_defs_insert:
                        replacement = extra_defs_insert + fixed_code

                                       
                    full_contract = original_source.replace(original_func_code, replacement, 1)
                    return full_contract
                
                                           
                elif original_func_code:
                    if self.include_comments:
                        print("   [Rebuild] Exact match failed, trying fuzzy match (ignoring whitespace)...")
                    
                               
                    target_lines = original_func_code.splitlines()
                    
                                          
                    clean_target = [l.strip() for l in target_lines if l.strip()]
                    
                    if clean_target:
                        first_target_line = clean_target[0]
                                         
                        for i, line in enumerate(lines):
                            if line.strip() == first_target_line:
                                                 
                                match = True
                                src_idx = i
                                tgt_idx = 0
                                match_start_line = i
                                match_end_line = i
                                
                                while tgt_idx < len(clean_target) and src_idx < len(lines):
                                               
                                    if not lines[src_idx].strip():
                                        src_idx += 1
                                        continue
                                    
                                              
                                                              
                                    if clean_target[tgt_idx] in lines[src_idx].strip():
                                        match_end_line = src_idx
                                        src_idx += 1
                                        tgt_idx += 1
                                    else:
                                        match = False
                                        break
                                
                                if match and tgt_idx == len(clean_target):
                                    if self.include_comments:
                                        print(f"   [Rebuild] Fuzzy match found at lines {match_start_line+1}-{match_end_line+1}")
                                    
                                            
                                    new_content_parts = []
                                    new_content_parts.append("".join(lines[:match_start_line]))
                                    
                                    if extra_defs_insert:
                                        new_content_parts.append(extra_defs_insert)
                                        
                                    new_content_parts.append(fixed_code)
                                    if not fixed_code.endswith('\n'):
                                        new_content_parts.append('\n')
                                        
                                    new_content_parts.append("".join(lines[match_end_line+1:]))
                                    
                                    full_contract = "".join(new_content_parts)
                                    return full_contract

                    if self.include_comments:
                        print("   [Rebuild] Fuzzy match failed.")

                else:
                                     
                    if self.include_comments:
                         print(f"   Warning: Function code not found in file (string match failed), and invalid lines.")
                    pass

            except Exception as e:
                print(f"Error: Failed to rebuild full contract: {e}")
                full_contract = None

                                               
        if full_contract is None:
            try:
                full_contract = self.build_simplified_contract(func_data, fixed_code)
            except Exception as e:
                return None

        return full_contract

      
if __name__ == "__main__":
                
    mock_context = {
        "function_name": "withdraw",
        "function_code": "function withdraw(uint amount) public onlyOwner {\n    require(balances[msg.sender] >= amount);\n    _transfer(msg.sender, address(0), amount);\n    msg.sender.transfer(amount);\n}",
        "solidity_version": "0.8.0",
        "contract_context": {
            "contract_name": "Vault",
            "state_variables": [
                {"code": "mapping(address => uint) public balances;", "name": "balances"},
                {"code": "address public owner;", "name": "owner"}
            ],
            "modifiers": [
                {"name": "onlyOwner", "code": "modifier onlyOwner() {\n    require(msg.sender == owner);\n    _;\n}"}
            ]
        },
        "called_functions": [
            {
                "name": "_transfer",
                "code": "function _transfer(address from, address to, uint amount) internal {\n    // Internal transfer logic\n    emit Transfer(from, to, amount);\n}"
            }
        ]
    }
    
    builder = CodeSliceBuilder()
    
    print("=== 代码切片模式 ===")
    print(builder.build_slice(mock_context))
    print("\n" + "="*50 + "\n")
    
    print("=== 完整合约模式 ===")
    print(builder.build_simplified_contract(mock_context))
    print("\n" + "="*50 + "\n")
    
              
    fixed_code = "function withdraw(uint amount) public onlyOwner {\n    require(balances[msg.sender] >= amount, \"Insufficient balance\");\n    _transfer(msg.sender, address(0), amount);\n    (bool success, ) = msg.sender.call{value: amount}(\"\");\n    require(success, \"Transfer failed\");\n}"
    print("=== 使用修复代码的完整合约模式 ===")
    print(builder.build_simplified_contract(mock_context, fixed_code))
    
    print("\n=== 重构完整合约模式 ===")
    print(builder.rebuild_full_contract(mock_context, fixed_code))

