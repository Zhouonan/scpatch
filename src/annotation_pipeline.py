\
\
\
   

import os
import sys
import json
import argparse
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from tqdm import tqdm

            
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.database.db_manager import DBManager
from src.tools.llm_annotator import LLMAnnotator, AnnotationConfig


class AnnotationPipeline:
               
    
    def __init__(
        self,
        db_manager: DBManager,
        annotator: LLMAnnotator,
        save_interval: int = 10,
        concurrency: int = 5
    ):
\
\
\
\
\
\
\
\
           
        self.db_manager = db_manager
        self.annotator = annotator
        self.save_interval = save_interval
        self.concurrency = concurrency
    
    async def process_item(self, func_data: Dict, semaphore: asyncio.Semaphore) -> Tuple[Dict, Optional[Dict]]:
                      
        async with semaphore:
                                                               
            annotation = await asyncio.to_thread(self.annotator.annotate_function, func_data)
            return func_data, annotation

    async def run_async(self, functions_data: List[Dict]):
                      
        total = len(functions_data)
        print(f"\n[3/4] 开始LLM标注（并发数: {self.concurrency}, 每{self.save_interval}条保存一次）...")
        
        annotated_count = 0
        failed_count = 0
        buffer = []
        
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self.process_item(func_data, semaphore) for func_data in functions_data]
        
        with tqdm(total=total, desc="标注进度") as pbar:
            for coro in asyncio.as_completed(tasks):
                func_data, annotation = await coro
                
                func_name = func_data.get('function_name', 'unknown')
                contract_name = func_data.get('contract_context', {}).get('contract_name', 'unknown')

                if annotation:
                                
                    func_data['llm_audit'] = annotation
                    buffer.append(func_data)
                    annotated_count += 1
                    
                    pbar.set_postfix({
                        'success': annotated_count,
                        'failed': failed_count,
                        'current': f"{contract_name}.{func_name}"
                    })
                else:
                    failed_count += 1
                    pbar.set_postfix({
                        'success': annotated_count,
                        'failed': failed_count,
                        'current': f"FAILED: {contract_name}.{func_name}"
                    })
                
                      
                if len(buffer) >= self.save_interval:
                    print(f"\n  [保存中] 保存 {len(buffer)} 条标注结果到数据库...")
                                          
                    self._save_annotations(buffer)
                    buffer.clear()
                
                pbar.update(1)
        
                
        if buffer:
            print(f"\n  [保存中] 保存最后 {len(buffer)} 条标注结果到数据库...")
            self._save_annotations(buffer)
            
        return annotated_count, failed_count

    def run(
        self,
        dataset_types: Optional[List[str]] = None,
        dataset_names: Optional[List[str]] = None,
        limit: Optional[int] = None,
        only_with_slither: bool = False,
        skip_already_annotated: bool = True,
        select_vulnerable_functions: bool = False
    ):
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
        print("LLM标注流水线 - 阶段1")
        print("="*80)
        
                      
        print("\n[1/4] 查询数据库...")
        functions = self._query_functions(
            dataset_types=dataset_types,
            dataset_names=dataset_names,
            only_with_slither=only_with_slither,
            skip_already_annotated=skip_already_annotated,
            select_vulnerable_functions=select_vulnerable_functions
        )
        
        if not functions:
            print("没有需要标注的数据")
            return
        
                 
        if limit:
            functions = functions[:limit]
        
        total = len(functions)
        print(f"找到 {total} 条需要标注的数据")
        
                 
        print("\n[2/4] 准备标注数据...")
        functions_data = self._prepare_function_data(functions)
        
                      
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            annotated_count, failed_count = loop.run_until_complete(self.run_async(functions_data))
        finally:
            loop.close()
        
               
        print("\n[4/4] 标注完成！")
        print(f"\n{'='*80}")
        print(f"标注结果统计:")
        print(f"  总处理数: {total}")
        print(f"  成功标注: {annotated_count}")
        print(f"  失败标注: {failed_count}")
        print(f"  成功率: {annotated_count/total*100:.1f}%")
        print(f"{'='*80}")
        
                
        self.annotator.print_stats()
    
    def _query_functions(
        self,
        dataset_types: Optional[List[str]],
        dataset_names: Optional[List[str]],
        only_with_slither: bool,
        skip_already_annotated: bool,
        select_vulnerable_functions: bool = False
    ) -> List:
                       
        session = self.db_manager.get_session()
        try:
            from src.database.models import SmartContractFunction
            from sqlalchemy import or_, cast, String, text
            
            query = session.query(SmartContractFunction)
            
                  
            if dataset_types:
                query = query.filter(SmartContractFunction.dataset_type.in_(dataset_types))
            
            if dataset_names:
                query = query.filter(SmartContractFunction.dataset_name.in_(dataset_names))
            
            if only_with_slither:
                                       
                query = query.filter(SmartContractFunction.slither_result.isnot(None))
            
            if skip_already_annotated:
                              
                                    
                query = query.filter(cast(SmartContractFunction.llm_audit, String) == 'null')

                                   
            if select_vulnerable_functions:
                query = query.filter(
                    or_(
                        SmartContractFunction.is_vulnerable == True,
                                         
                        text("json_extract(slither_result, '$.is_vulnerable') = true")
                    )
                )
            return query.all()
        finally:
            session.close()
    
    def _prepare_function_data(self, functions: List) -> List[Dict]:
                        
        functions_data = []
        
        for func in functions:

            func_data = {
                'function_name': func.function_name,
                'function_code': func.function_code,
                'function_signature': func.function_signature,
                'contract_context': func.contract_context or {},
                'called_functions': func.called_functions or [],
                'caller_functions': func.caller_functions or [],
                'slither_result': func.slither_result or {},
                'start_line': func.start_line,
                'end_line': func.end_line,
                'contract_path': func.contract_path,
                'label': func.label
            }
            
                         
            func_data['_db_id'] = func.id
            func_data['_sample_id'] = func.sample_id
            
            functions_data.append(func_data)
        
        return functions_data
    
    def _save_annotations(self, functions_data: List[Dict]):
                        
        session = self.db_manager.get_session()
        try:
            from src.database.models import SmartContractFunction
            
            for func_data in functions_data:
                db_id = func_data.get('_db_id')
                if not db_id:
                    continue
                
                           
                llm_audit = func_data.get('llm_audit')
                if not llm_audit:
                    continue
                
                         
                func = session.query(SmartContractFunction).filter_by(id=db_id).first()
                if func:
                    func.llm_audit = llm_audit
                    
                                             
                    if llm_audit.get('reasoning'):
                        reasoning = llm_audit['reasoning']
                                               
                        if isinstance(reasoning, list):
                            func.reasoning = '\n'.join(str(item) for item in reasoning)
                        else:
                            func.reasoning = str(reasoning)
                                             
                                
                    if func.raw_data:
                        func.raw_data['llm_audit'] = llm_audit
                    else:
                        func.raw_data = {'llm_audit': llm_audit}
                
            session.commit()
            
        except Exception as e:
            session.rollback()
            print(f"保存标注结果时出错: {e}")
            raise
        finally:
            session.close()


def main():
             
    parser = argparse.ArgumentParser(description='LLM标注流水线 - 阶段1')
    
           
    parser.add_argument(
        '--db-path',
        type=str,
        default='sqlite:///smart_contracts.db',
        help='数据库路径'
    )
    
            
    parser.add_argument(
        '--dataset-types',
        type=str,
        nargs='+',
        choices=['wild', 'curated'],
        help='数据集类型 (可多选)'
    )
    parser.add_argument(
        '--dataset-names',
        type=str,
        nargs='+',
        help='数据集名称 (可多选)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='最大处理数量'
    )
    parser.add_argument(
        '--include-without-slither',
        action='store_true',
        help='包含没有Slither结果的数据'
    )
    parser.add_argument(
        '--reannotate',
        action='store_true',
        help='重新标注已有LLM标注的数据'
    )
    parser.add_argument(
        '--select-vulnerable',
        action='store_true',
        default=False,
        help='选取漏洞或者slither检测为漏洞的函数'
    )

           
    parser.add_argument(
        '--api-key',
        type=str,
        default=None,
        help='OpenAI API Key (默认从环境变量OPENAI_API_KEY读取)'
    )
    parser.add_argument(
        '--base-url',
        type=str,
        default='https://api.deepseek.com',
        help='API Base URL (支持OpenAI兼容接口)'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='deepseek-chat',
        help='模型名称'
    )
    parser.add_argument(
        '--temperature',
        type=float,
        default=0.1,
        help='生成温度'
    )
                          
                         
                   
                       
                         
       
    
          
    parser.add_argument(
        '--save-interval',
        type=int,
        default=10,
        help='每处理多少条数据保存一次'
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=5,
        help='并发请求数量'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='输出详细信息（包括LLM的完整响应）'
    )
    
    args = parser.parse_args()
    
               
    api_key = args.api_key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("错误: 请提供API Key (通过--api-key参数或OPENAI_API_KEY环境变量)")
        sys.exit(1)
    
           
    print("初始化组件...")
    
         
    db_manager = DBManager(db_path=args.db_path)
    
            
    config = AnnotationConfig(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
        temperature=args.temperature,
        verbose=args.verbose
    )
    annotator = LLMAnnotator(config)
    
         
    pipeline = AnnotationPipeline(
        db_manager=db_manager,
        annotator=annotator,
        save_interval=args.save_interval,
        concurrency=args.concurrency
    )
    
        
    try:
        pipeline.run(
            dataset_types=args.dataset_types,
            dataset_names=args.dataset_names,
            limit=args.limit,
            only_with_slither=not args.include_without_slither,
            skip_already_annotated=not args.reannotate,
            select_vulnerable_functions=args.select_vulnerable
        )
    except KeyboardInterrupt:
        print("\n\n用户中断，正在保存已处理的数据...")
                             
        print("已保存！")
    except Exception as e:
        print(f"\n发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

