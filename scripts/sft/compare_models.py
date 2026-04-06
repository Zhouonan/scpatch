\
\
\
   

import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict
from tabulate import tabulate

            
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.database.db_manager import DBManager
from src.tools.llm_annotator import LLMAnnotator, AnnotationConfig


class ModelComparator:
                
    
    def __init__(self, db_manager: DBManager):
        self.db_manager = db_manager
        self.results = []
    
    def select_random_functions(
        self,
        num_samples: int = 10,
        min_lines: int = 5,
        max_lines: int = 100,
        balance_ratio: float = 0.5
    ) -> List[str]:
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
           
        import random
        
        session = self.db_manager.get_session()
        try:
            from src.database.models import SmartContractFunction
            from sqlalchemy import func
            
                      
            num_positive = int(num_samples * balance_ratio)
            num_negative = num_samples - num_positive
            
            print(f"正在选择样本...")
            print(f"  目标数量: {num_samples} (vulnerable: {num_positive}, safe: {num_negative})")
            print(f"  长度范围: {min_lines}-{max_lines} 行")
            
            selected_ids = []
            
                              
            if num_positive > 0:
                vulnerable_query = session.query(SmartContractFunction).filter(
                    SmartContractFunction.is_vulnerable == True,
                    SmartContractFunction.slither_result.isnot(None)
                )
                
                      
                vulnerable_funcs = []
                for func in vulnerable_query.all():
                    if func.function_code:
                        lines = len([l for l in func.function_code.split('\n') if l.strip()])
                        if min_lines <= lines <= max_lines:
                            vulnerable_funcs.append(func)
                
                print(f"  找到 {len(vulnerable_funcs)} 个符合条件的vulnerable样本")
                
                if len(vulnerable_funcs) < num_positive:
                    print(f"  ⚠️  可用样本不足，只能选择 {len(vulnerable_funcs)} 个")
                    num_positive = len(vulnerable_funcs)
                
                selected_vuln = random.sample(vulnerable_funcs, num_positive)
                selected_ids.extend([f.sample_id for f in selected_vuln])
            
                        
            if num_negative > 0:
                safe_query = session.query(SmartContractFunction).filter(
                    SmartContractFunction.is_vulnerable == False,
                    SmartContractFunction.slither_result.isnot(None)
                )
                
                      
                safe_funcs = []
                for func in safe_query.all():
                    if func.function_code:
                        lines = len([l for l in func.function_code.split('\n') if l.strip()])
                        if min_lines <= lines <= max_lines:
                            safe_funcs.append(func)
                
                print(f"  找到 {len(safe_funcs)} 个符合条件的safe样本")
                
                if len(safe_funcs) < num_negative:
                    print(f"  ⚠️  可用样本不足，只能选择 {len(safe_funcs)} 个")
                    num_negative = len(safe_funcs)
                
                selected_safe = random.sample(safe_funcs, num_negative)
                selected_ids.extend([f.sample_id for f in selected_safe])
            
                  
            random.shuffle(selected_ids)
            
            print(f"  ✅ 共选择了 {len(selected_ids)} 个样本")
            return selected_ids
            
        finally:
            session.close()
    
    def compare_models(
        self,
        function_id: str,
        model_configs: List[Dict],
        verbose: bool = False
    ) -> Dict:
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
           
        print("="*80)
        print(f"多模型对比测试")
        print("="*80)
        
                       
        print(f"\n[1/3] 从数据库获取函数: {function_id}")
        func_data = self._get_function_data(function_id)
        if not func_data:
            print(f"❌ 未找到函数: {function_id}")
            return None
        
        func_name = func_data.get('function_name', 'unknown')
        contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')
        slither_result = func_data.get('slither_result', {})
        slither_says = 'vulnerable' if slither_result.get('is_vulnerable') else 'safe'
        
        print(f"✅ 找到函数: {contract_name}.{func_name}")
        print(f"   Slither判断: {slither_says}")
        if slither_result.get('vulnerability_details'):
            vuln_types = [v.get('type') for v in slither_result['vulnerability_details']]
            print(f"   Slither发现: {', '.join(vuln_types[:3])}{'...' if len(vuln_types) > 3 else ''}")
        
                       
        print(f"\n[2/3] 使用 {len(model_configs)} 个模型进行标注...")
        
        results = []
        for i, config_dict in enumerate(model_configs, 1):
            model_name = config_dict.get('model', 'unknown')
            print(f"\n{'='*80}")
            print(f"[{i}/{len(model_configs)}] 测试模型: {model_name}")
            print(f"{'='*80}")
            
                  
            config = AnnotationConfig(
                api_key=config_dict['api_key'],
                base_url=config_dict.get('base_url', 'https://api.openai.com/v1'),
                model=model_name,
                temperature=config_dict.get('temperature', 0.1),
                max_tokens=config_dict.get('max_tokens', 2000),
                verbose=verbose
            )
            
                    
            import time
            start_time = time.time()
            
                      
            annotator = LLMAnnotator(config)
            annotation = annotator.annotate_function(func_data)
            
                  
            elapsed_time = time.time() - start_time
            
            if annotation:
                result = {
                    'model': model_name,
                    'config': config_dict,
                    'annotation': annotation,
                    'stats': annotator.stats.copy(),
                    'elapsed_time': elapsed_time
                }
                results.append(result)
                print(f"✅ {model_name} 标注完成 (耗时: {elapsed_time:.2f}秒)")
            else:
                print(f"❌ {model_name} 标注失败 (耗时: {elapsed_time:.2f}秒)")
                results.append({
                    'model': model_name,
                    'config': config_dict,
                    'annotation': None,
                    'error': 'Annotation failed',
                    'elapsed_time': elapsed_time
                })
        
                 
        print(f"\n[3/3] 生成对比报告...")
        comparison = self._generate_comparison(
            function_info={
                'function_id': function_id,
                'function_name': func_name,
                'contract_name': contract_name,
                'slither_result': slither_says,
                'slither_details': slither_result.get('vulnerability_details', [])
            },
            results=results
        )
        
        self.results.append(comparison)
        return comparison
    
    def _get_function_data(self, function_id: str) -> Dict:
                        
        session = self.db_manager.get_session()
        try:
            from src.database.models import SmartContractFunction
            
            func = session.query(SmartContractFunction).filter_by(
                sample_id=function_id
            ).first()
            
            if not func:
                return None
            
                    
            if func.raw_data:
                func_data = func.raw_data
            else:
                func_data = {
                    'function_name': func.function_name,
                    'function_code': func.function_code,
                    'contract_context': func.contract_context or {},
                    'called_functions': func.called_functions or [],
                    'slither_result': func.slither_result or {}
                }
            
            return func_data
        finally:
            session.close()
    
    def _generate_comparison(self, function_info: Dict, results: List[Dict]) -> Dict:
                    
        comparison = {
            'function': function_info,
            'models': [],
            'summary': {}
        }
        
                   
        for result in results:
            if result.get('annotation'):
                ann = result['annotation']
                comparison['models'].append({
                    'model': result['model'],
                    'label': ann.get('label'),
                    'severity': ann.get('severity', 0),
                    'confidence': ann.get('confidence', 0),
                    'vulnerability_types': ann.get('vulnerability_types', []),
                    'agrees_with_slither': ann.get('slither_agreement', None),
                    'analysis': ann.get('analysis', ''),
                    'reasoning': ann.get('reasoning', ''),
                    'slither_critique': ann.get('slither_critique', ''),
                    'tokens_used': result['stats'].get('total_tokens_used', 0),
                    'elapsed_time': result.get('elapsed_time', 0)
                })
            else:
                comparison['models'].append({
                    'model': result['model'],
                    'error': result.get('error', 'Unknown error'),
                    'elapsed_time': result.get('elapsed_time', 0)
                })
        
                
        successful_models = [m for m in comparison['models'] if 'error' not in m]
        if successful_models:
            labels = [m['label'] for m in successful_models]
            comparison['summary'] = {
                'total_models': len(results),
                'successful': len(successful_models),
                'failed': len(results) - len(successful_models),
                'agree_on_vulnerable': labels.count('vulnerable'),
                'agree_on_safe': labels.count('safe'),
                'consensus': all(l == labels[0] for l in labels) if labels else False,
                'avg_severity': sum(m['severity'] for m in successful_models) / len(successful_models),
                'avg_confidence': sum(m['confidence'] for m in successful_models) / len(successful_models),
                'avg_tokens': sum(m['tokens_used'] for m in successful_models) / len(successful_models),
                'avg_elapsed_time': sum(m['elapsed_time'] for m in successful_models) / len(successful_models)
            }
        
        return comparison
    
    def print_comparison(self, comparison: Dict):
                    
        print("\n" + "="*80)
        print("📊 对比报告")
        print("="*80)
        
              
        func_info = comparison['function']
        print(f"\n📝 函数信息:")
        print(f"   ID: {func_info['function_id']}")
        print(f"   名称: {func_info['contract_name']}.{func_info['function_name']}")
        print(f"   Slither判断: {func_info['slither_result']}")
        
                
        print(f"\n📋 模型结果对比:")
        
        table_data = []
        for model in comparison['models']:
            if 'error' in model:
                table_data.append([
                    model['model'],
                    '❌ 失败',
                    '-',
                    '-',
                    '-',
                    '-',
                    f"{model.get('elapsed_time', 0):.2f}s",
                    model['error'][:20]
                ])
            else:
                agree_symbol = '✅' if model['agrees_with_slither'] else '⚠️'
                table_data.append([
                    model['model'],
                    model['label'],
                    f"{model['severity']:.1f}",
                    f"{model['confidence']:.2f}",
                    f"{agree_symbol}",
                    model['tokens_used'],
                    f"{model['elapsed_time']:.2f}s",
                    '✓'
                ])
        
        headers = ['模型', '判断', '严重度', '置信度', '同意Slither', 'Tokens', '耗时', '状态']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        
                
        print(f"\n🔍 发现的漏洞类型:")
        for model in comparison['models']:
            if 'error' not in model and model['vulnerability_types']:
                print(f"   {model['model']}: {', '.join(model['vulnerability_types'])}")
            elif 'error' not in model:
                print(f"   {model['model']}: (无)")
        
              
        if comparison['summary']:
            summary = comparison['summary']
            print(f"\n📈 统计摘要:")
            print(f"   共测试: {summary['total_models']} 个模型")
            print(f"   成功: {summary['successful']}, 失败: {summary['failed']}")
            print(f"   判断为vulnerable: {summary['agree_on_vulnerable']} 个")
            print(f"   判断为safe: {summary['agree_on_safe']} 个")
            print(f"   是否一致: {'✅ 是' if summary['consensus'] else '❌ 否'}")
            print(f"   平均严重度: {summary['avg_severity']:.2f}")
            print(f"   平均置信度: {summary['avg_confidence']:.2f}")
            print(f"   平均Tokens: {summary['avg_tokens']:.0f}")
            print(f"   平均耗时: {summary['avg_elapsed_time']:.2f}秒")
        
                  
        print(f"\n💡 详细分析:")
        for i, model in enumerate(comparison['models'], 1):
            if 'error' in model:
                continue
            
            print(f"\n[{i}] {model['model']}:")
            print(f"   分析: {model['analysis'][:200]}...")
            
            if not model['agrees_with_slither'] and model['slither_critique']:
                print(f"   与Slither分歧: {model['slither_critique'][:150]}...")
    
    def save_comparison(self, comparison: Dict, output_file: str):
                           
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)
        print(f"\n💾 对比结果已保存到: {output_file}")
    
    def batch_compare(
        self,
        function_ids: List[str],
        model_configs: List[Dict],
        verbose: bool = False,
        output_dir: str = None
    ) -> List[Dict]:
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
           
        print("="*80)
        print(f"批量对比测试 - 共 {len(function_ids)} 个函数")
        print("="*80)
        
        all_comparisons = []
        
        for i, func_id in enumerate(function_ids, 1):
            print(f"\n{'#'*80}")
            print(f"# 测试进度: {i}/{len(function_ids)}")
            print(f"{'#'*80}\n")
            
            comparison = self.compare_models(
                function_id=func_id,
                model_configs=model_configs,
                verbose=verbose
            )
            
            if comparison:
                all_comparisons.append(comparison)
                
                        
                if output_dir:
                    import os
                    os.makedirs(output_dir, exist_ok=True)
                    output_file = os.path.join(output_dir, f"{func_id}.json")
                    self.save_comparison(comparison, output_file)
        
                
        print("\n" + "="*80)
        print("📊 综合对比报告")
        print("="*80)
        self._print_batch_summary(all_comparisons)
        
        return all_comparisons
    
    def _print_batch_summary(self, all_comparisons: List[Dict]):
                         
        if not all_comparisons:
            print("没有成功的对比结果")
            return
        
        total_functions = len(all_comparisons)
        
                   
        model_stats = {}
        
        for comparison in all_comparisons:
            for model_result in comparison['models']:
                if 'error' in model_result:
                    continue
                
                model_name = model_result['model']
                if model_name not in model_stats:
                    model_stats[model_name] = {
                        'total': 0,
                        'correct_vs_slither': 0,
                        'disagreements': 0,
                        'avg_confidence': 0,
                        'avg_severity': 0,
                        'total_tokens': 0,
                        'vulnerable_calls': 0,
                        'safe_calls': 0
                    }
                
                stats = model_stats[model_name]
                stats['total'] += 1
                
                if model_result['agrees_with_slither']:
                    stats['correct_vs_slither'] += 1
                else:
                    stats['disagreements'] += 1
                
                stats['avg_confidence'] += model_result['confidence']
                stats['avg_severity'] += model_result['severity']
                stats['total_tokens'] += model_result['tokens_used']
                stats['avg_elapsed_time'] = stats.get('avg_elapsed_time', 0) + model_result.get('elapsed_time', 0)
                
                if model_result['label'] == 'vulnerable':
                    stats['vulnerable_calls'] += 1
                else:
                    stats['safe_calls'] += 1
        
               
        for model_name, stats in model_stats.items():
            if stats['total'] > 0:
                stats['avg_confidence'] /= stats['total']
                stats['avg_severity'] /= stats['total']
                stats['avg_elapsed_time'] /= stats['total']
                stats['agreement_rate'] = stats['correct_vs_slither'] / stats['total']
        
              
        print(f"\n测试了 {total_functions} 个函数\n")
        
        table_data = []
        for model_name, stats in sorted(model_stats.items()):
            table_data.append([
                model_name,
                stats['total'],
                f"{stats['agreement_rate']*100:.1f}%",
                f"{stats['avg_confidence']:.2f}",
                f"{stats['avg_severity']:.1f}",
                f"{stats['vulnerable_calls']}/{stats['safe_calls']}",
                f"{stats['avg_elapsed_time']:.2f}s",
                f"{stats['total_tokens']:.0f}"
            ])
        
        headers = ['模型', '成功数', '与Slither一致率', '平均置信度', '平均严重度', 'Vuln/Safe', '平均耗时', '总Tokens']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        
                
        print(f"\n📈 模型共识分析:")
        consensus_count = 0
        for comparison in all_comparisons:
            if comparison['summary'].get('consensus'):
                consensus_count += 1
        
        consensus_rate = consensus_count / total_functions * 100
        print(f"   完全一致的函数: {consensus_count}/{total_functions} ({consensus_rate:.1f}%)")
        
                   
        max_disagreement = 0
        most_controversial = None
        
        for comparison in all_comparisons:
            summary = comparison['summary']
            vuln_count = summary.get('agree_on_vulnerable', 0)
            safe_count = summary.get('agree_on_safe', 0)
            disagreement = abs(vuln_count - safe_count) / summary.get('total_models', 1)
            
            if disagreement > max_disagreement:
                max_disagreement = disagreement
                most_controversial = comparison
        
        if most_controversial:
            func_info = most_controversial['function']
            print(f"\n⚠️  分歧最大的函数:")
            print(f"   {func_info['contract_name']}.{func_info['function_name']}")
            print(f"   Slither: {func_info['slither_result']}")
            summary = most_controversial['summary']
            print(f"   判断为vulnerable: {summary['agree_on_vulnerable']} 个模型")
            print(f"   判断为safe: {summary['agree_on_safe']} 个模型")


def main():
    parser = argparse.ArgumentParser(description='多模型对比测试工具')
    
               
    parser.add_argument(
        '--function-id',
        type=str,
        help='函数的sample_id（与--auto-select互斥）'
    )
    parser.add_argument(
        '--auto-select',
        type=int,
        metavar='NUM',
        help='自动随机选择NUM个函数进行测试'
    )
    parser.add_argument(
        '--min-lines',
        type=int,
        default=5,
        help='函数最小行数（用于auto-select，默认5）'
    )
    parser.add_argument(
        '--max-lines',
        type=int,
        default=100,
        help='函数最大行数（用于auto-select，默认100）'
    )
    parser.add_argument(
        '--balance',
        type=float,
        default=0.5,
        help='正样本（vulnerable）比例（用于auto-select，默认0.5表示1:1）'
    )
    
         
    parser.add_argument(
        '--db-path',
        type=str,
        default='sqlite:///smart_contracts.db',
        help='数据库路径'
    )
    
            
    parser.add_argument(
        '--models-config',
        type=str,
        help='模型配置JSON文件路径'
    )
    
              
    parser.add_argument(
        '--models',
        type=str,
        nargs='+',
        help='要测试的模型名称列表'
    )
    parser.add_argument(
        '--api-key',
        type=str,
        help='API Key'
    )
    parser.add_argument(
        '--base-url',
        type=str,
        default='https://api.openai.com/v1',
        help='API Base URL'
    )
    
        
    parser.add_argument(
        '--output',
        type=str,
        help='保存对比结果的JSON文件路径'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='显示LLM的完整响应'
    )
    
    args = parser.parse_args()
    
            
    model_configs = []
    
    if args.models_config:
                 
        with open(args.models_config, 'r') as f:
            config_data = json.load(f)
            model_configs = config_data.get('models', [])
    elif args.models:
                  
        api_key = args.api_key or os.getenv('OPENAI_API_KEY')
        if not api_key:
            print("错误: 请提供API Key (--api-key 或 OPENAI_API_KEY 环境变量)")
            sys.exit(1)
        
        for model in args.models:
            model_configs.append({
                'model': model,
                'api_key': api_key,
                'base_url': args.base_url,
                'temperature': 0.1,
                'max_tokens': 2000
            })
    else:
        print("错误: 请提供 --models-config 或 --models")
        sys.exit(1)
    
    if not model_configs:
        print("错误: 没有找到模型配置")
        sys.exit(1)
    
    print(f"将使用 {len(model_configs)} 个模型进行对比测试")
    
          
    if not args.function_id and not args.auto_select:
        print("错误: 请提供 --function-id 或 --auto-select")
        sys.exit(1)
    
    if args.function_id and args.auto_select:
        print("错误: --function-id 和 --auto-select 不能同时使用")
        sys.exit(1)
    
         
    db_manager = DBManager(db_path=args.db_path)
    comparator = ModelComparator(db_manager)
    
          
    try:
        if args.auto_select:
                    
            function_ids = comparator.select_random_functions(
                num_samples=args.auto_select,
                min_lines=args.min_lines,
                max_lines=args.max_lines,
                balance_ratio=args.balance
            )
            
            if not function_ids:
                print("错误: 没有找到符合条件的函数")
                sys.exit(1)
            
                  
            all_comparisons = comparator.batch_compare(
                function_ids=function_ids,
                model_configs=model_configs,
                verbose=args.verbose,
                output_dir=args.output if args.output else None
            )
            
                              
            if args.output:
                import os
                summary_file = os.path.join(args.output, 'summary.json')
                with open(summary_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'total_functions': len(all_comparisons),
                        'comparisons': all_comparisons
                    }, f, indent=2, ensure_ascii=False)
                print(f"\n💾 综合报告已保存到: {summary_file}")
        
        else:
                    
            comparison = comparator.compare_models(
                function_id=args.function_id,
                model_configs=model_configs,
                verbose=args.verbose
            )
            
            if comparison:
                      
                comparator.print_comparison(comparison)
                
                      
                if args.output:
                    comparator.save_comparison(comparison, args.output)
        
    except KeyboardInterrupt:
        print("\n\n用户中断")
    except Exception as e:
        print(f"\n发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

