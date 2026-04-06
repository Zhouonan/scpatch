from sqlalchemy import Column, Integer, String, Text, Boolean, Float, JSON, create_engine, Index
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func
import datetime

Base = declarative_base()

class SmartContractFunction(Base):
                    
    __tablename__ = 'smart_contract_functions'

          
    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String(255), unique=True, index=True, comment="唯一样本ID")
    
          
    dataset_name = Column(String(100), index=True, comment="数据集名称")
    dataset_type = Column(String(50), index=True, comment="数据集类型(wild/curated)")
    contract_path = Column(String(500), comment="合约文件路径")
    contract_name = Column(String(200), index=True, comment="合约名称")
    
          
    function_name = Column(String(200), index=True, comment="函数名称")
    function_signature = Column(String(500), comment="函数签名")
    function_code = Column(Text, comment="函数源码")
    solidity_version = Column(String(50), comment="Solidity版本")
    start_line = Column(Integer, comment="开始行号")
    end_line = Column(Integer, comment="结束行号")
    
          
    is_vulnerable = Column(Boolean, index=True, default=False, comment="是否有漏洞")
    vulnerability_types = Column(JSON, comment="漏洞类型列表")                
    severity = Column(Float, default=0.0, comment="严重程度评分 (0-10)")
    reasoning = Column(Text, comment="漏洞分析/推理")
    
            
    label = Column(JSON, comment="标注结果")
    slither_result = Column(JSON, comment="Slither静态分析结果")
    llm_audit = Column(JSON, comment="LLM审计结果")
                                               

                      
    contract_context = Column(JSON, comment="合约上下文(继承、状态变量等)")
    caller_functions = Column(JSON, comment="调用者函数信息")
    called_functions = Column(JSON, comment="被调用者函数信息")
    
            
    raw_data = Column(JSON, comment="原始完整JSON数据")
    
         
    created_at = Column(String(50), default=func.now())
    
                 
    __table_args__ = (
        Index('idx_dataset_vuln', 'dataset_name', 'is_vulnerable'),
        Index('idx_type_vuln', 'dataset_type', 'is_vulnerable'),
    )

    def __repr__(self):
        return f"<Function(id={self.id}, name='{self.function_name}', vuln={self.is_vulnerable})>"





