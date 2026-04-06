# SmartBugs 数据集处理指南

完整的 SmartBugs Wild 和 SmartBugs Curated 数据集处理流程

## 目录

1. [快速开始](#快速开始)
2. [数据集下载](#数据集下载)
3. [安装依赖](#安装依赖)
4. [处理流程](#处理流程)
5. [输出说明](#输出说明)
6. [常见问题](#常见问题)

---

## 快速开始

```bash
# 1. 下载数据集
git clone https://github.com/smartbugs/smartbugs-wild.git
git clone https://github.com/smartbugs/smartbugs-curated.git

# 2. 安装依赖
pip install tqdm pandas

# 3. 运行处理pipeline
python smartbugs_pipeline.py
```

---

## 数据集下载

### SmartBugs Wild (47K+ 合约)

```bash
git clone https://github.com/smartbugs/smartbugs-wild.git
cd smartbugs-wild
# 数据在 contracts/ 目录下
```

### SmartBugs Curated (143 个精选合约)

```bash
git clone https://github.com/smartbugs/smartbugs-curated.git
cd smartbugs-curated
# 数据按漏洞类型组织:
# - access_control/
# - arithmetic/
# - bad_randomness/
# - denial_of_service/
# - front_running/
# - reentrancy/
# - time_manipulation/
# - unchecked_low_level_calls/
```

---

## 安装依赖

### 基本依赖

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
tqdm
pandas
numpy
```

### 可选：Slither (用于精确AST解析)

```bash
pip install slither-analyzer
# 需要安装 solc
pip install py-solc-x
```

如果使用 Slither，在配置中设置 `use_slither: True`

---

## 处理流程

### 整体架构

```
SmartBugs Wild (47K)      SmartBugs Curated (143)
         ↓                          ↓
   [版本检测]                  [直接使用]
         ↓                          ↓
   [质量过滤]                  [Ground Truth]
         ↓                          ↓
   [函数提取]                  [函数提取]
         ↓                          ↓
   [自动标注]                  [已标注]
         ↓                          ↓
      [训练集]                   [测试集]
```

### 阶段详解

#### 阶段1: 合约级处理

```python
from smartbugs_processor import SmartBugsProcessor

processor = SmartBugsProcessor(
    wild_dir='./smartbugs-wild',
    curated_dir='./smartbugs-curated',
    output_dir='./processed_smartbugs'
)

wild_contracts, curated_contracts = processor.process_both_datasets()
```

**输出:**
- `curated_processed.json`: Curated 的143个合约信息
- `wild_processed.json`: Wild 的所有合约信息
- `wild_filtered.json`: 质量过滤后的 Wild 合约
- `version_analysis.json`: 版本分布统计

#### 阶段2: 函数级处理

```python
from function_level_processor import FunctionLevelProcessor

processor = FunctionLevelProcessor(use_slither=False)

# 提取函数 + 上下文
functions = processor.process_contract_to_functions(
    contract_file='path/to/contract.sol',
    contract_info={
        'solidity_version': '0.8.0',
        'dataset': 'wild'
    }
)
```

**每个函数样本包含:**
```python
{
    "function_code": "function withdraw() public { ... }",
    "function_name": "withdraw",
    "function_signature": "withdraw()",
    "caller_functions": [
        {"name": "emergency", "signature": "emergency()"}
    ],
    "called_functions": [
        {"name": "transfer", "type": "external"}
    ],
    "contract_context": {
        "contract_name": "Token",
        "inheritance": ["ERC20"],
        "state_variables": [...],
        "modifiers": ["onlyOwner"]
    },
    "ast_features": {
        "has_external_calls": true,
        "has_state_changes": true,
        "uses_tx_origin": false,
        ...
    },
    "metadata": {
        "solidity_version": "0.8.0",
        "dataset": "wild"
    },
    "labels": null  # Wild数据无标注
}
```

#### 阶段3: 标注处理

```python
# Curated: 已有ground truth标注
# Wild: 自动标注

def auto_label_with_slither(contract_file):
    """使用Slither自动标注"""
    from slither import Slither
    slither = Slither(contract_file)
    
    vulnerabilities = []
    for detector in slither.detectors:
        results = detector.detect()
        vulnerabilities.extend(results)
    
    return vulnerabilities
```

**标注格式:**
```python
{
    "has_vulnerability": true,
    "vulnerability_types": ["reentrancy", "unchecked_call"],
    "confidence": 0.85,
    "source": "auto_labeled" 或 "ground_truth"
}
```

#### 阶段4: 数据集划分

**时序划分策略:**

```python
版本时代分类:
- early_legacy (0.4.x): 旧版本，大量传统漏洞
- late_legacy (0.5.x - 0.6.x): 过渡版本
- transition (0.7.x): 重要更新
- modern (0.8.x+): 现代版本，内置安全特性

数据集划分:
- Train: early_legacy + late_legacy  (模拟历史数据)
- Val: transition (一半)               (验证泛化)
- Test: transition (另一半) + modern + Curated (评估真实性能)
```

**为什么这样划分？**
- ✅ 模拟真实部署场景（用旧数据训练，新数据测试）
- ✅ 评估时序泛化能力（能否检测新版本的漏洞）
- ✅ Curated全部作为测试集（提供可靠的ground truth）

#### 阶段5: 生成微调格式

```python
{
    "input": """
### Target Function:
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}

### Caller Functions:
- emergencyWithdraw()

### Called Functions:
- call (external)

### Contract Context:
- Contract: VulnerableBank
- Inherits: Ownable
    """,
    
    "label": "reentrancy",
    
    "metadata": {
        "contract_file": "...",
        "function_name": "withdraw",
        "solidity_version": "0.4.25",
        "dataset": "curated"
    }
}
```

---

## 输出说明

### 目录结构

```
processed_smartbugs/
├── stage1_contract_level/
│   ├── curated_processed.json      # Curated 合约信息
│   ├── wild_processed.json         # Wild 合约信息
│   ├── wild_filtered.json          # 过滤后的 Wild
│   ├── version_analysis.json       # 版本统计
│   └── processing_report.txt       # 处理报告
│
├── stage2_function_level/
│   └── all_functions.json          # 所有函数级样本
│
├── stage3_labeling/
│   └── labeled_dataset.json        # 标注后的数据集
│
├── stage4_splits/
│   ├── train.json                  # 训练集
│   ├── val.json                    # 验证集
│   ├── test.json                   # 测试集
│   └── splits_summary.json         # 划分摘要
│
└── stage5_final/
    ├── train_formatted.jsonl       # 微调格式训练集
    ├── val_formatted.jsonl         # 微调格式验证集
    └── test_formatted.jsonl        # 微调格式测试集
```

### 关键文件说明

#### 1. all_functions.json

每个函数的完整信息，包括代码、上下文、AST特征。

#### 2. splits_summary.json

```json
{
    "train_size": 15000,
    "val_size": 3000,
    "test_size": 3500,
    "total": 21500,
    "curated_in_test": 143
}
```

#### 3. train_formatted.jsonl

JSONL 格式，每行一个样本，直接用于微调:

```json
{"input": "...", "label": "reentrancy", "metadata": {...}}
{"input": "...", "label": "safe", "metadata": {...}}
...
```

---

## 使用配置

### 基本配置

```python
config = {
    # 输入路径
    'smartbugs_wild_dir': './smartbugs-wild',
    'smartbugs_curated_dir': './smartbugs-curated',
    
    # 输出路径
    'output_dir': './processed_smartbugs',
    
    # 处理选项
    'test_mode': False,  # True: 只处理100个合约测试
    'use_slither': False,  # True: 使用Slither精确解析
    'auto_label_wild': True,  # True: 自动标注Wild数据
}
```

### 测试模式

```python
# 快速测试（只处理100个合约）
config['test_mode'] = True

pipeline = SmartBugsPipeline(config)
pipeline.run_full_pipeline()
# 预计耗时: 2-5分钟
```

### 完整模式

```python
# 处理全部数据
config['test_mode'] = False

pipeline = SmartBugsPipeline(config)
pipeline.run_full_pipeline()
# 预计耗时: 2-4小时（取决于机器性能）
```

---

## 常见问题

### Q1: 处理速度太慢怎么办？

**A:** 
1. 使用测试模式先验证流程
2. 如果不需要精确AST，设置 `use_slither: False`
3. 多进程并行处理（修改代码加入 multiprocessing）

### Q2: 内存不足怎么办？

**A:**
1. 批量处理，不要一次加载所有数据
2. 减少 Wild 的处理数量
3. 增加系统swap空间

### Q3: Slither安装失败？

**A:**
```bash
# 方法1: 使用conda
conda install -c conda-forge slither-analyzer

# 方法2: 不使用Slither
config['use_slither'] = False  # 使用正则解析
```

### Q4: Wild数据标注准确吗？

**A:**
- 自动标注（工具）的准确率约60-70%
- 建议结合多个工具（Slither + Mythril + Securify）
- 关键: Curated作为测试集，提供可靠的ground truth
- 训练集的噪声可以通过数据量弥补

### Q5: 如何验证处理结果？

**A:**
```python
# 加载结果
import json

with open('processed_smartbugs/stage4_splits/splits_summary.json') as f:
    summary = json.load(f)
    print(summary)

# 检查样本
with open('processed_smartbugs/stage5_final/train_formatted.jsonl') as f:
    first_sample = json.loads(f.readline())
    print(first_sample['input'])
    print(first_sample['label'])
```

### Q6: 如何自定义处理逻辑？

**A:**
修改 `smartbugs_pipeline.py` 中的相应方法:

```python
class SmartBugsPipeline:
    def stage_3_labeling(self, function_dataset):
        # 自定义标注逻辑
        pass
    
    def format_input(self, func_data):
        # 自定义输入格式
        pass
```

---

## 下一步

处理完数据后，可以:

1. **加载数据进行微调**
```python
import json

# 加载训练集
train_data = []
with open('processed_smartbugs/stage5_final/train_formatted.jsonl') as f:
    for line in f:
        train_data.append(json.loads(line))

# 开始微调...
```

2. **数据统计分析**
```python
from collections import Counter

labels = [sample['label'] for sample in train_data]
print(Counter(labels))
```

3. **与版本控制系统集成**
```python
# 结合你之前的版本控制系统
from version_control_system import VersionDetector

detector = VersionDetector()
# 进一步分析版本分布...
```

---

## 联系与反馈

如有问题，欢迎交流！

**预期效果:**
- 处理时间: 2-4小时（完整模式）
- 函数样本数: 15,000 - 25,000
- Curated benchmark: 143个高质量测试样本
- 版本覆盖: 0.4.x - 0.8.x

祝研究顺利！ 🚀
