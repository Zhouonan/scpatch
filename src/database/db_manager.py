import json
import random
from typing import List, Dict, Optional, Union, Tuple, Any, Set
from pathlib import Path
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from src.database.models import Base, SmartContractFunction

                   
try:
    from src.database.models_fix import VulnerabilityFix, FixPair
    _fix_models_available = True
except ImportError:
    _fix_models_available = False

from src.tools.swc_mapper import map_types_to_swc_ids

class DBManager:
    def __init__(self, db_path: str = "sqlite:///smart_contracts.db"):
\
\
\
           
        self.engine = create_engine(db_path)
                        
        Base.metadata.create_all(self.engine, checkfirst=True)
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        return self.Session()

    def save_functions(self, functions_data: List[Dict], batch_size: int = 1000):
\
\
           
        session = self.Session()
        try:
            total = len(functions_data)
            print(f"正在保存 {total} 条数据到数据库...")

                    
            batch_data = []
            for func_data in functions_data:
                metadata = func_data.get('metadata', {})
                context = func_data.get('contract_context', {})
                label = func_data.get('label')            

                dataset = metadata.get('dataset', 'unknown')
                contract_name = context.get('contract_name', 'unknown')
                func_name = func_data.get('function_name', 'unknown')
                sample_id = f"{dataset}_{contract_name}_{func_name}_{func_data.get('start_line', 0)}"

                is_vulnerable = label.get('is_vulnerable', False) if label else False
                vuln_details = label.get('vulnerability_details', []) if label else []
                vuln_types = [v.get('type') for v in vuln_details] if vuln_details else []
                if not vuln_types and is_vulnerable:
                     if label and label.get('vulnerability_type'):
                         vuln_types.append(label.get('vulnerability_type'))

                record = {
                    'sample_id': sample_id,
                    'dataset_name': dataset,
                    'dataset_type': metadata.get('dataset_type', 'wild'),
                    'contract_path': metadata.get('contract_file', ''),
                    'contract_name': contract_name,
                    'function_name': func_name,
                    'function_signature': func_data.get('function_signature', ''),
                    'function_code': func_data.get('function_code', ''),
                    'solidity_version': metadata.get('solidity_version', ''),
                    'start_line': func_data.get('start_line'),
                    'end_line': func_data.get('end_line'),
                    'is_vulnerable': is_vulnerable,
                    'vulnerability_types': vuln_types,                             
                    'severity': label.get('severity', 0.0) if label else 0.0,
                    'reasoning': label.get('reasoning', '') if label else '',
                    'label': label,
                    'slither_result': func_data.get('slither_result', {}),
                    'llm_audit': func_data.get('llm_audit', None),
                    'contract_context': func_data.get('contract_context', {}),
                    'caller_functions': func_data.get('caller_functions', []),
                    'called_functions': func_data.get('called_functions', []),
                    'raw_data': func_data
                }
                batch_data.append(record)

                         
            for i in range(0, total, batch_size):
                batch = batch_data[i:i+batch_size]
                if not batch:
                    continue
                    
                stmt = sqlite_insert(SmartContractFunction.__table__).values(batch)
                
                                               
                                                  
                update_dict = {
                    col.name: stmt.excluded[col.name]
                    for col in stmt.table.columns 
                    if col.name not in ['sample_id', 'id', 'created_at']
                }
                
                do_update_stmt = stmt.on_conflict_do_update(
                    index_elements=['sample_id'],
                    set_=update_dict
                )
                
                session.execute(do_update_stmt)
                session.commit()
                
                print(f"  已处理 {min(i + batch_size, total)}/{total}...")

            print(f"保存完成! 共处理 {total} 条记录。")
            
        except Exception as e:
            session.rollback()
            print(f"保存数据时出错: {e}")
            raise
        finally:
            session.close()

    def query_dataset(
        self, 
        dataset_types: List[str] = None,
        dataset_names: List[str] = None,
        vuln_types: List[str] = None,
        min_severity: float = 0,
        limit: int = None
    ) -> List[SmartContractFunction]:
\
\
           
        session = self.Session()
        try:
            query = session.query(SmartContractFunction)
            
            if dataset_types:
                query = query.filter(SmartContractFunction.dataset_type.in_(dataset_types))
            
            if dataset_names:
                query = query.filter(SmartContractFunction.dataset_name.in_(dataset_names))
                
            if vuln_types:
                                              
                                                               
                                                     
                pass
            
            if min_severity > 0:
                query = query.filter(SmartContractFunction.severity >= min_severity)
                
            if limit:
                query = query.limit(limit)
                
            return query.all()
        finally:
            session.close()

    def export_balanced_dataset(
        self,
        total_samples: int,
        positive_ratio: float = 0.5,
        dataset_types: List[str] = None,
        random_seed: int = 42
    ) -> Tuple[List[Dict], Dict]:
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
           
        random.seed(random_seed)
        session = self.Session()
        
        try:
                    
            base_query = session.query(SmartContractFunction)
            if dataset_types:
                base_query = base_query.filter(SmartContractFunction.dataset_type.in_(dataset_types))
            
                      
            pos_query = base_query.filter(SmartContractFunction.is_vulnerable == True)
            neg_query = base_query.filter(SmartContractFunction.is_vulnerable == False)
            
                                      
            pos_ids = [id[0] for id in pos_query.with_entities(SmartContractFunction.id).all()]
            neg_ids = [id[0] for id in neg_query.with_entities(SmartContractFunction.id).all()]
            
            total_pos_available = len(pos_ids)
            total_neg_available = len(neg_ids)
            
                    
            target_pos = int(total_samples * positive_ratio)
            target_neg = total_samples - target_pos
            
                            
            actual_pos = min(target_pos, total_pos_available)
            actual_neg = min(target_neg, total_neg_available)
            
            print(f"数据集导出请求: 总数={total_samples}, 正样本比例={positive_ratio:.0%}")
            print(f"数据库存量: 正样本={total_pos_available}, 负样本={total_neg_available}")
            print(f"实际采样: 正样本={actual_pos}, 负样本={actual_neg}")
            
                    
            selected_pos_ids = random.sample(pos_ids, actual_pos)
            selected_neg_ids = random.sample(neg_ids, actual_neg)
            
            all_selected_ids = selected_pos_ids + selected_neg_ids
            random.shuffle(all_selected_ids)
            
                      
                                  
            results = []
            chunk_size = 500
            for i in range(0, len(all_selected_ids), chunk_size):
                chunk_ids = all_selected_ids[i:i+chunk_size]
                records = session.query(SmartContractFunction).filter(
                    SmartContractFunction.id.in_(chunk_ids)
                ).all()
                
                                                     
                for r in records:
                    if r.raw_data:
                        results.append(r.raw_data)
                    else:
                                               
                        results.append({
                            'function_code': r.function_code,
                            'label': {
                                'is_vulnerable': r.is_vulnerable,
                                'vulnerability_types': r.vulnerability_types,
                                'reasoning': r.reasoning
                            },
                            'metadata': {
                                'dataset': r.dataset_name,
                                'dataset_type': r.dataset_type
                            }
                        })
            
            stats = {
                'requested_total': total_samples,
                'actual_total': len(results),
                'positive_count': actual_pos,
                'negative_count': actual_neg,
                'positive_ratio': actual_pos / len(results) if results else 0
            }
            
            return results, stats
            
        finally:
            session.close()

    def get_stats(self):
                       
        session = self.Session()
        try:
            total = session.query(func.count(SmartContractFunction.id)).scalar()
            vuln = session.query(func.count(SmartContractFunction.id)).filter(
                SmartContractFunction.is_vulnerable == True
            ).scalar()
            
            datasets = session.query(
                SmartContractFunction.dataset_name, 
                func.count(SmartContractFunction.id)
            ).group_by(SmartContractFunction.dataset_name).all()
            
            stats = {
                'total_functions': total,
                'vulnerable_functions': vuln,
                'safe_functions': total - vuln,
                'vulnerability_ratio': vuln / total if total > 0 else 0,
                'datasets': dict(datasets)
            }
            
                            
            if _fix_models_available:
                from src.database.models_fix import VulnerabilityFix
                total_fixes = session.query(func.count(VulnerabilityFix.id)).scalar()
                compile_success = session.query(func.count(VulnerabilityFix.id))\
                    .filter(VulnerabilityFix.compiles == True).scalar()
                slither_success = session.query(func.count(VulnerabilityFix.id))\
                    .filter(VulnerabilityFix.slither_passed == True).scalar()
                
                stats['fix_stats'] = {
                    'total_fixes': total_fixes,
                    'compile_success': compile_success,
                    'slither_success': slither_success,
                    'compile_success_rate': compile_success / total_fixes if total_fixes > 0 else 0,
                    'slither_success_rate': slither_success / total_fixes if total_fixes > 0 else 0
                }
            
            return stats
        finally:
            session.close()
    
    def save_fix(self, fix_data: Dict) -> Optional[int]:
\
\
\
\
\
\
\
\
           
        if not _fix_models_available:
            print("错误: 修复表模型不可用")
            return None
        
        from src.database.models_fix import VulnerabilityFix
        
        session = self.Session()
        try:
                         
            function_id = fix_data.get('function_id')
            existing_fixes = session.query(VulnerabilityFix)\
                .filter_by(function_id=function_id)\
                .order_by(VulnerabilityFix.fix_version.desc())\
                .first()
            
            next_version = 1
            if existing_fixes:
                next_version = existing_fixes.fix_version + 1
            
                    
            vuln_types = fix_data.get('vulnerabilities_fixed', []) or []
                                                              
            swc_ids = map_types_to_swc_ids(vuln_types)
            fix_record = VulnerabilityFix(
                function_id=function_id,
                sample_id=fix_data.get('sample_id'),
                fix_version=next_version,
                original_code=fix_data.get('original_code'),
                fixed_code=fix_data.get('fixed_code'),
                fix_analysis=fix_data.get('fix_analysis'),
                vulnerabilities_fixed=vuln_types,
                swc_ids=swc_ids,
                original_severity=fix_data.get('original_severity'),
                compiles=fix_data.get('compiles', False),
                slither_passed=fix_data.get('slither_passed', False),
                remaining_issues=fix_data.get('remaining_issues', []),
                verification_details=fix_data.get('verification_details'),
                model_name=fix_data.get('model_name'),
                fix_attempts=fix_data.get('fix_attempts', 1),
                raw_fix_data=fix_data.get('raw_fix_data')
            )
            
            session.add(fix_record)
            session.commit()
            
            return fix_record.id
            
        except Exception as e:
            session.rollback()
            print(f"保存修复记录时出错: {e}")
            return None
        finally:
            session.close()

                                   
                                    
                                   

    def _sqlite_table_columns(self, table_name: str) -> Set[str]:
\
\
           
        cols: Set[str] = set()
        with self.engine.connect() as conn:
            rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
            for r in rows:
                                                               
                if len(r) >= 2:
                    cols.add(str(r[1]))
        return cols

    def _ensure_sqlite_column(self, table_name: str, column_name: str, column_type_sql: str = "TEXT") -> bool:
\
\
           
        cols = self._sqlite_table_columns(table_name)
        if column_name in cols:
            return False
        with self.engine.connect() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type_sql}"))
            conn.commit()
        return True

    def backfill_vulnerability_fixes_swc_ids(
        self,
        exclude_swcs: Optional[List[str]] = None,
        overwrite_vulnerabilities_fixed: bool = False,
        dry_run: bool = False,
        batch_size: int = 500,
        verbose: bool = True,
    ) -> Dict[str, Any]:
\
\
\
\
\
\
\
           
        if not _fix_models_available:
            raise RuntimeError("Fix models not available (src.database.models_fix import failed).")

                                                           
        added = self._ensure_sqlite_column("vulnerability_fixes", "swc_ids", "TEXT")
        if verbose and added:
            print("Added column vulnerability_fixes.swc_ids (TEXT) for SWC backfill.")

        session = self.Session()
        stats = {
            "total": 0,
            "updated": 0,
            "skipped_no_types": 0,
            "skipped_unchanged": 0,
            "errors": 0,
            "mode": "overwrite_vulnerabilities_fixed" if overwrite_vulnerabilities_fixed else "write_swc_ids",
            "dry_run": dry_run,
        }

        try:
            q = session.query(VulnerabilityFix).yield_per(batch_size)
            for fix in q:
                stats["total"] += 1
                try:
                    vuln_types = fix.vulnerabilities_fixed or []
                    if not vuln_types:
                        stats["skipped_no_types"] += 1
                        continue

                    swc_ids = map_types_to_swc_ids(vuln_types, exclude_swcs=exclude_swcs)

                    if overwrite_vulnerabilities_fixed:
                        current = fix.vulnerabilities_fixed or []
                        if list(current) == swc_ids:
                            stats["skipped_unchanged"] += 1
                            continue
                        if not dry_run:
                            fix.vulnerabilities_fixed = swc_ids
                        stats["updated"] += 1
                    else:
                        current = getattr(fix, "swc_ids", None) or []
                        if list(current) == swc_ids:
                            stats["skipped_unchanged"] += 1
                            continue
                        if not dry_run:
                            fix.swc_ids = swc_ids
                        stats["updated"] += 1

                    if not dry_run and stats["updated"] % batch_size == 0:
                        session.commit()

                except Exception:
                    stats["errors"] += 1

            if not dry_run:
                session.commit()
            return stats
        finally:
            session.close()

    def count_vulnerability_fixes_by_swc(
        self,
        exclude_swcs: Optional[List[str]] = None,
        only_successful: bool = False,
        use_fallback_mapping_if_missing: bool = True,
        batch_size: int = 1000,
    ) -> Dict[str, int]:
\
\
\
\
\
\
\
           
        if not _fix_models_available:
            raise RuntimeError("Fix models not available (src.database.models_fix import failed).")

        from collections import Counter

        session = self.Session()
        try:
            q = session.query(VulnerabilityFix)
            if only_successful:
                q = q.filter(VulnerabilityFix.compiles.is_(True)).filter(VulnerabilityFix.slither_passed.is_(True))

            counter: Counter[str] = Counter()
            for fix in q.yield_per(batch_size):
                swcs = getattr(fix, "swc_ids", None) or []
                if (not swcs) and use_fallback_mapping_if_missing:
                    swcs = map_types_to_swc_ids(fix.vulnerabilities_fixed or [], exclude_swcs=exclude_swcs)
                else:
                    swcs = map_types_to_swc_ids(swcs, exclude_swcs=exclude_swcs)

                                              
                for s in set(swcs):
                    counter[s] += 1

            return dict(counter.most_common())
        finally:
            session.close()
    
    def query_fixes(
        self,
        function_ids: List[int] = None,
        only_successful: bool = False,
        min_quality_score: float = None,
        limit: int = None
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
\
\
           
        if not _fix_models_available:
            print("错误: 修复表模型不可用")
            return []
        
        from src.database.models_fix import VulnerabilityFix
        
        session = self.Session()
        try:
            query = session.query(VulnerabilityFix)
            
            if function_ids:
                query = query.filter(VulnerabilityFix.function_id.in_(function_ids))
            
            if only_successful:
                query = query.filter(VulnerabilityFix.compiles == True)\
                            .filter(VulnerabilityFix.slither_passed == True)
            
            if min_quality_score is not None:
                query = query.filter(VulnerabilityFix.fix_quality_score >= min_quality_score)
            
            if limit:
                query = query.limit(limit)
            
            return query.all()
        finally:
            session.close()
    
    def export_fix_pairs(
        self,
        only_successful: bool = True,
        dataset_names: List[str] = None,
        output_format: str = 'dict'
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
           
        if not _fix_models_available:
            print("错误: 修复表模型不可用")
            return []
        
        from src.database.models_fix import VulnerabilityFix
        
        session = self.Session()
        try:
                           
            query = session.query(SmartContractFunction, VulnerabilityFix)\
                .join(VulnerabilityFix, SmartContractFunction.id == VulnerabilityFix.function_id)
            
            if only_successful:
                query = query.filter(VulnerabilityFix.compiles == True)\
                            .filter(VulnerabilityFix.slither_passed == True)
            
            if dataset_names:
                query = query.filter(SmartContractFunction.dataset_name.in_(dataset_names))
            
            results = query.all()
            
            fix_pairs = []
            for func, fix in results:
                pair = {
                    'fix_id': fix.id,
                    'function_id': func.id,
                    'sample_id': func.sample_id,
                    'dataset_name': func.dataset_name,
                    'dataset_type': func.dataset_type,
                    'contract_name': func.contract_name,
                    'function_name': func.function_name,
                    'vulnerable_code': fix.original_code,
                    'fixed_code': fix.fixed_code,
                    'fix_analysis': fix.fix_analysis,
                    'vulnerability_types': fix.vulnerabilities_fixed,
                    'severity': fix.original_severity,
                    'compiles': fix.compiles,
                    'slither_passed': fix.slither_passed,
                    'fix_version': fix.fix_version,
                    'model_name': fix.model_name
                }
                fix_pairs.append(pair)
            
            return fix_pairs
            
        finally:
            session.close()





