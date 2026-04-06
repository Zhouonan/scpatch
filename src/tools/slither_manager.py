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
   

import os
import re
from pathlib import Path
from typing import Optional, Dict, List
from contextlib import contextmanager

try:
    from slither.slither import Slither
    SLITHER_AVAILABLE = True
except ImportError:
    print("Warning: Slither not available.")
    SLITHER_AVAILABLE = False

try:
    import solcx
    SOLCX_AVAILABLE = True
except ImportError:
    print("Warning: py-solc-x not available. Version switching disabled.")
    SOLCX_AVAILABLE = False

          
TARGET_DETECTORS = {
               
    'UninitializedStateVarsDetection', 'UninitializedStorageVars', 'UninitializedLocalVars', 
    'UnusedStateVars', 'CouldBeConstant', 'CouldBeImmutable', 'VarReadUsingThis',
    'PredeclarationUsageLocal', 'FunctionInitializedState',
    
                
    'ConstantPragma', 'IncorrectSolc', 'LockedEther', 'UnprotectedUpgradeable',
    'ConstantFunctionsAsm', 'ConstantFunctionsState', 'MissingInheritance',
    
               
    'ArbitrarySendEth', 'Suicidal', 'ExternalFunction', 'UnimplementedFunctionDetection',
    'DeadCode', 'ProtectedVariables', 'DomainSeparatorCollision', 
    'ChainlinkFeedRegistry', 'PythDeprecatedFunctions', 'OptimismDeprecation',
    
                    
    'ArbitrarySendErc20NoPermit', 'ArbitrarySendErc20Permit', 'IncorrectERC20InterfaceDetection',
    'IncorrectERC721InterfaceDetection', 'UnindexedERC20EventParameters',
    
                            
    'ReentrancyBenign', 'ReentrancyReadBeforeWritten', 'ReentrancyEth', 
    'ReentrancyNoGas', 'ReentrancyEvent',
    
                             
    'TxOrigin', 'Assembly', 'LowLevelCalls', 'UnusedReturnValues', 'UncheckedTransfer',
    'ControlledDelegateCall', 'Timestamp', 'MultipleCallsInLoop', 'IncorrectStrictEquality',
    'DeprecatedStandards', 'RightToLeftOverride', 'TooManyDigits', 'UncheckedLowLevel',
    'UncheckedSend', 'VoidConstructor', 'TypeBasedTautology', 'BooleanEquality',
    'BooleanConstantMisuse', 'DivideBeforeMultiply', 'MappingDeletionDetection',
    'ArrayLengthAssignment', 'RedundantStatements', 'BadPRNG', 'CostlyOperationsInLoop',
    'AssertStateChange', 'WriteAfterWrite', 'MsgValueInLoop', 'DelegatecallInLoop',
    'CacheArrayLength', 'IncorrectUsingFor', 'EncodePackedCollision', 
    'IncorrectOperatorExponentiation', 'TautologicalCompare', 'ReturnBomb',
    'ChronicleUncheckedPrice', 'PythUncheckedConfidence', 'PythUncheckedPublishTime',
    
               
    'ShadowingAbstractDetection', 'StateShadowing', 'LocalShadowing', 'BuiltinSymbolShadowing',
    
                              
    'ShiftParameterMixup', 'StorageSignedIntegerArray', 'UninitializedFunctionPtrsConstructor',
    'ABIEncoderV2Array', 'ArrayByReference', 'EnumConversion', 'MultipleConstructorSchemes',
    'PublicMappingNested', 'ReusedBaseConstructor', 'IncorrectReturn', 'ReturnInsteadOfLeave',
    
                    
    'MissingEventsAccessControl', 'MissingEventsArithmetic', 'MissingZeroAddressValidation',
    'ModifierDefaultDetection', 'IncorrectUnaryExpressionDetection', 
    'OutOfOrderRetryable', 'GelatoUnprotectedRandomness'
}

class SlitherManager:
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
       
    
    def __init__(self, debug: bool = False):
\
\
\
\
\
           
        self.debug = debug
        self._version_cache = {}            
        self._installed_versions = set()            
        self._old_env = {}           
        
    def extract_solidity_version(self, contract_file: str) -> Optional[str]:
\
\
\
\
\
\
\
\
           
        try:
            with open(contract_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
                                     
            pragma_matches = re.findall(r'pragma\s+solidity\s+([^;]+);', content, re.MULTILINE)
            if not pragma_matches:
                return None
            
                             
            version_spec = pragma_matches[0].strip()
            
                                          
            version_matches = re.findall(r'(\d+)\.(\d+)(?:\.(\d+))?', version_spec)
            if not version_matches:
                return None
            
                      
                                      
            if '^' in version_spec:
                major, minor, patch = version_matches[0]
                patch = patch if patch else '0'
                return f"{major}.{minor}.{patch}"
            
                             
            if '~' in version_spec:
                major, minor, patch = version_matches[0]
                patch = patch if patch else '0'
                return f"{major}.{minor}.{patch}"
            
                                     
            if '>=' in version_spec:
                ge_match = re.search(r'>=\s*(\d+)\.(\d+)(?:\.(\d+))?', version_spec)
                if ge_match:
                    major, minor, patch = ge_match.groups()
                    patch = patch if patch else '0'
                    return f"{major}.{minor}.{patch}"
            
                              
            if '>' in version_spec and '>=' not in version_spec:
                gt_match = re.search(r'>\s*(\d+)\.(\d+)(?:\.(\d+))?', version_spec)
                if gt_match:
                    major, minor, patch = gt_match.groups()
                    patch = patch if patch else '0'
                    return f"{major}.{minor}.{int(patch)+1}"
            
                                      
            if '||' in version_spec:
                major, minor, patch = version_matches[0]
                patch = patch if patch else '0'
                return f"{major}.{minor}.{patch}"
            
                               
            major, minor, patch = version_matches[0]
            patch = patch if patch else '0'
            return f"{major}.{minor}.{patch}"
            
        except Exception as e:
            if self.debug:
                print(f"Warning: 无法提取版本 {contract_file}: {e}")
        return None
    
    def detect_required_features(self, contract_file: str) -> str:
\
\
\
\
\
\
\
\
           
        try:
            with open(contract_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            min_version = "0.4.11"                    
            
                      
                                  
            if re.search(r'\bemit\s+\w+\s*\(', content):
                min_version = max(min_version, "0.4.21", key=lambda v: tuple(int(x) for x in v.split('.')))
            
                                       
            if re.search(r'\b(pure|view)\b', content):
                min_version = max(min_version, "0.4.16", key=lambda v: tuple(int(x) for x in v.split('.')))
            
                                         
            if re.search(r'\bconstructor\s*\(', content):
                min_version = max(min_version, "0.4.22", key=lambda v: tuple(int(x) for x in v.split('.')))
            
                                             
            if re.search(r'\brevert\s*\(["\']', content):
                min_version = max(min_version, "0.4.22", key=lambda v: tuple(int(x) for x in v.split('.')))
            
            return min_version
            
        except Exception as e:
            if self.debug:
                print(f"Warning: 检测特性失败 {contract_file}: {e}")
            return "0.4.11"
    
    def find_compatible_version(self, required_version: str) -> Optional[str]:
\
\
\
\
\
\
\
\
           
        if not SOLCX_AVAILABLE:
            return None
        
        try:
                     
            req_parts = [int(x) for x in required_version.split('.')]
            req_major, req_minor, req_patch = req_parts[0], req_parts[1], req_parts[2]
            
                                       
            min_supported_version = (0, 4, 11)
            if (req_major, req_minor, req_patch) < min_supported_version:
                if self.debug:
                    print(f"Note: 版本 {required_version} 低于最低支持版本 0.4.11，使用 0.4.11")
                return "0.4.11"
            
                        
            available_versions = solcx.get_installable_solc_versions()
            
                                  
            compatible_versions = []
            for ver in available_versions:
                ver_str = str(ver).lstrip('v')
                ver_parts = ver_str.split('.')
                if len(ver_parts) >= 2:
                    major, minor = int(ver_parts[0]), int(ver_parts[1])
                    if major == req_major and minor == req_minor:
                        compatible_versions.append(ver_str)
            
            if compatible_versions:
                           
                if required_version in compatible_versions:
                    return required_version
                             
                return compatible_versions[0]
            
                                       
            closest_ver = None
            min_diff = float('inf')
            for ver in available_versions:
                ver_str = str(ver).lstrip('v')
                ver_parts = ver_str.split('.')
                if len(ver_parts) >= 3:
                    major = int(ver_parts[0])
                    minor = int(ver_parts[1])
                    patch = int(ver_parts[2])
                    
                                 
                    if (major, minor, patch) < min_supported_version:
                        continue
                    
                            
                    diff = abs(major - req_major) * 10000 + abs(minor - req_minor) * 100 + abs(patch - req_patch)
                    if diff < min_diff:
                        min_diff = diff
                        closest_ver = ver_str
            
            return closest_ver if closest_ver else "0.4.11"
            
        except Exception as e:
            if self.debug:
                print(f"Warning: 查找兼容版本失败: {e}")
            return "0.4.11"
    
    def setup_solc_version(self, contract_file: str) -> Optional[str]:
\
\
\
\
\
\
\
\
           
        if not SOLCX_AVAILABLE:
            if self.debug:
                print("Warning: py-solc-x 不可用")
            return None
        
        try:
                              
            pragma_version = self.extract_solidity_version(contract_file)
            if not pragma_version:
                if self.debug:
                    print(f"Warning: 无法提取版本信息")
                return None
            
                              
            feature_min_version = self.detect_required_features(contract_file)
            
                          
            def version_tuple(v):
                return tuple(int(x) for x in v.split('.'))
            
            if version_tuple(feature_min_version) > version_tuple(pragma_version):
                if self.debug:
                    print(f"Note: pragma声明 {pragma_version}，但语法特性需要 >= {feature_min_version}")
                required_version = feature_min_version
            else:
                required_version = pragma_version
            
                     
            if required_version in self._version_cache:
                try:
                    solcx.set_solc_version(required_version, silent=True)
                except:
                    pass
                return self._version_cache[required_version]
            
                           
            installed_versions = [str(v).lstrip('v') for v in solcx.get_installed_solc_versions()]
            
                         
            actual_version = required_version
            
            if required_version not in installed_versions:
                          
                compatible_version = self.find_compatible_version(required_version)
                
                if compatible_version and compatible_version in installed_versions:
                    if self.debug:
                        print(f"使用已安装的兼容版本 {compatible_version} (请求: {required_version})")
                    actual_version = compatible_version
                elif compatible_version:
                    if self.debug:
                        print(f"安装兼容版本 {compatible_version} (请求: {required_version})")
                    try:
                        solcx.install_solc(compatible_version)
                        actual_version = compatible_version
                        self._installed_versions.add(compatible_version)
                    except Exception as e:
                        print(f"Warning: 无法安装版本 {compatible_version}: {e}")
                        return None
                else:
                    print(f"Warning: 无法找到兼容版本 {required_version}")
                    return None
            
                        
            try:
                solcx.set_solc_version(actual_version, silent=True)
                if self.debug:
                    print(f"Setting Solidity version to {actual_version}")
            except Exception as e:
                print(f"Warning: 无法设置 Solidity 版本 {actual_version}: {e}")
                return None
            
                        
            solc_path = self._get_solc_path(actual_version)
            
            if solc_path:
                self._version_cache[required_version] = solc_path
                if self.debug:
                    print(f"Found solc at: {solc_path}")
                return solc_path
            
            if self.debug:
                print(f"Using environment variable for solc {actual_version}")
            return "SOLCX_ENV"
            
        except Exception as e:
            print(f"Warning: 设置编译器版本失败: {e}")
            return None
    
    def _get_solc_path(self, version: str) -> Optional[str]:
                                
        try:
                                    
            if hasattr(solcx, 'get_executable'):
                try:
                    solc_path = solcx.get_executable(version=version)
                    if solc_path and os.path.exists(solc_path):
                        return str(solc_path)
                except:
                    pass
            
                          
            home_dir = Path.home()
            possible_dirs = [
                home_dir / '.solcx' / f'solc-v{version}',
                home_dir / '.solcx' / 'bin' / f'solc-v{version}',
                home_dir / '.solcx' / f'solc-v{version}' / 'bin',
            ]
            
            for solc_dir in possible_dirs:
                if solc_dir.exists():
                    for possible_name in ['solc', f'solc-{version}', 'solc.exe']:
                        possible_path = solc_dir / possible_name
                        if possible_path.exists() and os.access(possible_path, os.X_OK):
                            return str(possible_path)
                    
                          
                    for root, dirs, files in os.walk(solc_dir):
                        for file in files:
                            if file == 'solc' or file == 'solc.exe':
                                full_path = os.path.join(root, file)
                                if os.access(full_path, os.X_OK):
                                    return full_path
            
                                 
            try:
                if hasattr(solcx, 'install') and hasattr(solcx.install, 'get_executable'):
                    solc_path = solcx.install.get_executable(version)
                    if solc_path and os.path.exists(solc_path):
                        return str(solc_path)
            except:
                pass
        
        except Exception as e:
            if self.debug:
                print(f"Warning: 获取编译器路径失败: {e}")
        
        return None
    
    def _setup_environment(self, solc_path: str):
                              
                 
        env_vars_to_save = ['SOLC', 'SOLC_VERSION', 'PATH']
        for var in env_vars_to_save:
            self._old_env[var] = os.environ.get(var)
        
                        
        solc_select_vars = ['SOLC_SELECT_VERSION', 'SOLC_SELECT', 'SOLC_SELECT_DIR']
        for var in solc_select_vars:
            if var in os.environ:
                del os.environ[var]
        
                 
        if solc_path != "SOLCX_ENV" and os.path.exists(solc_path):
            os.environ['SOLC'] = solc_path
            solc_dir = os.path.dirname(solc_path)
            old_path = os.environ.get('PATH', '')
            os.environ['PATH'] = f"{solc_dir}:{old_path}"
    
    def _restore_environment(self):
                     
        for var, value in self._old_env.items():
            if value is not None:
                os.environ[var] = value
            elif var in os.environ:
                del os.environ[var]
        self._old_env.clear()
    
    def get_slither(self, 
                    contract_file: str,
                    **kwargs) -> Optional[Slither]:
\
\
\
\
\
\
\
\
\
           
        if not SLITHER_AVAILABLE:
            print("Error: Slither not available. Please install: pip install slither-analyzer")
            return None
        
                  
        if not os.path.exists(contract_file):
            print(f"Error: Contract file not found: {contract_file}")
            return None
        
        try:
                        
            if self.debug:
                print(f"[1/4] Setting up compiler version for {os.path.basename(contract_file)}...")
            
            solc_path = self.setup_solc_version(contract_file)
            
            if not solc_path:
                print(f"Error: Failed to setup compiler version for {contract_file}")
                print("Possible reasons:")
                print("  - No pragma statement found")
                print("  - py-solc-x not installed: pip install py-solc-x")
                print("  - Compiler version not available")
                return None
            
            if self.debug:
                print(f"    ✓ Compiler setup complete: {solc_path}")
            
                       
            if self.debug:
                print(f"[2/4] Setting up environment variables...")
            
            self._setup_environment(solc_path)
            
            if self.debug:
                print(f"    ✓ Environment configured")
            
                            
            if self.debug:
                print(f"[3/4] Preparing Slither parameters...")
            
            slither_kwargs = {
                'solc_disable_warnings': True,
            }
            
                      
            if solc_path != "SOLCX_ENV" and os.path.exists(solc_path):
                slither_kwargs['solc'] = solc_path
                if self.debug:
                    print(f"    ✓ Using solc: {solc_path}")
            elif solc_path == "SOLCX_ENV":
                if self.debug:
                    print(f"    ✓ Using solc from environment")
            
                       
            slither_kwargs.update(kwargs)
            
                            
            if self.debug:
                print(f"[4/4] Creating Slither instance...")
            
            slither = Slither(contract_file, **slither_kwargs)
            
            if self.debug:
                if slither:
                    print(f"    ✓ Slither instance created successfully")
                    print(f"    ✓ Found {len(slither.contracts)} contract(s)")
                else:
                    print(f"    ✗ Slither instance creation failed")
            
            return slither
        
        except FileNotFoundError as e:
            print(f"Error: File not found: {e}")
            self._restore_environment()
            return None
        
        except Exception as e:
            print(f"Error creating Slither instance for {contract_file}")
            print(f"  Error type: {type(e).__name__}")
            print(f"  Error message: {str(e)}")
            
            if "solc" in str(e).lower():
                print(f"  Hint: This might be a compiler issue")
                print(f"       - Check if the contract can compile manually")
                print(f"       - Try: solc {contract_file}")
            
            if self.debug:
                print("\nFull traceback:")
                import traceback
                traceback.print_exc()
            
            self._restore_environment()
            return None
    
    @contextmanager
    def analyze_contract(self, 
                        contract_file: str,
                        **kwargs):
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
\
\
\
           
        slither = None
        try:
            slither = self.get_slither(contract_file, **kwargs)
            yield slither
        except GeneratorExit:
                          
            pass
        except Exception as e:
            if self.debug:
                print(f"Exception in analyze_contract: {e}")
                import traceback
                traceback.print_exc()
                                   
                                                    
        finally:
            self.cleanup()
    
    def cleanup(self):
                         
        self._restore_environment()
    
    def get_version_info(self, contract_file: str) -> Dict[str, str]:
\
\
\
\
\
\
\
\
           
        pragma_version = self.extract_solidity_version(contract_file)
        feature_version = self.detect_required_features(contract_file)
        
        return {
            'pragma_version': pragma_version,
            'feature_min_version': feature_version,
            'recommended_version': max(pragma_version or '0.4.11', feature_version, 
                                      key=lambda v: tuple(int(x) for x in v.split('.')))
        }


      
def analyze_with_slither(contract_file: str, 
                        debug: bool = False,
                        **kwargs):
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
       
    manager = SlitherManager(debug=debug)
    return manager.get_slither(contract_file, **kwargs)


if __name__ == "__main__":
          
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python slither_manager.py <contract_file>")
        sys.exit(1)
    
    contract_file = sys.argv[1]
    
    print("=" * 60)
    print("Slither Manager 测试")
    print("=" * 60)
    
    manager = SlitherManager(debug=True)
    
                 
    print("\n[1] 版本信息:")
    version_info = manager.get_version_info(contract_file)
    for key, value in version_info.items():
        print(f"    {key}: {value}")
    
                   
    print("\n[2] 使用Slither分析:")
    with manager.analyze_contract(contract_file) as slither:
        if slither:
            print(f"    成功! 找到 {len(slither.contracts)} 个合约")
            for contract in slither.contracts:
                print(f"    - {contract.name}: {len(contract.functions)} 个函数")
        else:
            print("    失败!")
    
    print("\n" + "=" * 60)