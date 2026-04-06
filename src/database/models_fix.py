from sqlalchemy import Column, Integer, String, Text, Boolean, Float, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.database.models import Base

class VulnerabilityFix(Base):
    __tablename__ = 'vulnerability_fixes'
    id = Column(Integer, primary_key=True, autoincrement=True)
    function_id = Column(Integer, ForeignKey('smart_contract_functions.id'), nullable=False, index=True, comment='关联的函数ID')
    sample_id = Column(String(255), index=True, comment='关联的样本ID')
    fix_version = Column(Integer, default=1, comment='修复版本号（支持多次修复）')
    original_code = Column(Text, comment='原始漏洞代码（带上下文）')
    fixed_code = Column(Text, comment='修复后的代码')
    fix_analysis = Column(Text, comment='修复分析')
    vulnerabilities_fixed = Column(JSON, comment='修复的漏洞类型列表')
    swc_ids = Column(JSON, comment="SWC IDs list, e.g. ['SWC-107', 'SWC-120']")
    original_severity = Column(Float, comment='原始严重程度')
    compiles = Column(Boolean, default=False, comment='是否编译通过')
    slither_passed = Column(Boolean, default=False, comment='Slither检查是否通过')
    remaining_issues = Column(JSON, comment='剩余问题列表')
    verification_details = Column(JSON, comment='详细验证信息')
    fix_quality_score = Column(Float, comment='修复质量评分（可选，人工或自动评估）')
    is_verified = Column(Boolean, default=False, comment='是否经过人工验证')
    verification_notes = Column(Text, comment='验证备注')
    model_name = Column(String(100), comment='使用的模型名称')
    model_temperature = Column(Float, comment='生成温度')
    fix_attempts = Column(Integer, default=1, comment='修复尝试次数')
    tokens_used = Column(Integer, comment='使用的token数')
    generation_time = Column(Float, comment='生成耗时（秒）')
    raw_fix_data = Column(JSON, comment='完整的修复结果JSON')
    created_at = Column(String(50), default=func.now(), comment='创建时间')
    updated_at = Column(String(50), onupdate=func.now(), comment='更新时间')
    __table_args__ = (Index('idx_function_version', 'function_id', 'fix_version'), Index('idx_fix_quality', 'compiles', 'slither_passed'), Index('idx_model', 'model_name'))

    def __repr__(self):
        return f'<VulnerabilityFix(id={self.id}, function_id={self.function_id}, version={self.fix_version})>'

class FixPair(Base):
    __tablename__ = 'fix_pairs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    fix_id = Column(Integer, ForeignKey('vulnerability_fixes.id'), index=True, comment='关联的修复记录ID')
    function_id = Column(Integer, ForeignKey('smart_contract_functions.id'), index=True, comment='关联的函数ID')
    vulnerable_code = Column(Text, comment='漏洞代码')
    fixed_code = Column(Text, comment='修复代码')
    vulnerability_types = Column(JSON, comment='漏洞类型')
    severity = Column(Float, comment='严重程度')
    is_training = Column(Boolean, default=True, comment='是否用于训练')
    is_validation = Column(Boolean, default=False, comment='是否用于验证')
    is_test = Column(Boolean, default=False, comment='是否用于测试')
    quality_checked = Column(Boolean, default=False, comment='是否通过质量检查')
    quality_score = Column(Float, comment='质量分数')
    dataset_name = Column(String(100), index=True, comment='所属数据集')
    created_at = Column(String(50), default=func.now())
    __table_args__ = (Index('idx_dataset_split', 'dataset_name', 'is_training', 'is_validation', 'is_test'), Index('idx_pair_quality', 'quality_checked', 'quality_score'))

    def __repr__(self):
        return f'<FixPair(id={self.id}, fix_id={self.fix_id})>'
