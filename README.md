# SCPatch: Automated Smart Contract Vulnerability Repair via Security-Constrained Policy Optimization

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)

This repository contains the official implementation and the `SCPATCH-BENCH` dataset for the paper: **SCPatch: Automated Smart Contract Vulnerability Repair via Security-Constrained Policy Optimization**.

## 📖 Overview

Smart contract vulnerabilities can lead to catastrophic financial losses. Existing learning-based repair methods often optimize proxy metrics (like syntactic similarity) that fail to guarantee the repaired code is compilable, secure, and semantically preserved. 

**SCPatch** bridges this gap by formulating smart contract repair as a **constrained optimization problem**. We treat security verification as a hard constraint rather than a soft reward signal. The framework integrates three synergistic procedures:

1. **Procedure I: Supervised Fine-Tuning (SFT)** with scope-aware context expansion to establish foundational repair capabilities.
2. **Procedure II: Multi-Signal Hybrid Retrieval Augmentation (RAG)** combining lexical (BM25), semantic (dense embeddings), and structural (MinHash) matching to dynamically incorporate relevant historical repairs.
3. **Procedure III: Security-Constrained Policy Optimization** using a Lagrangian-based policy gradient algorithm (GRPO) with a multi-stage verification pipeline (Solidity compilation, Slither, and Mythril) to enforce security compliance.

Extensive experiments on `SCPATCH-BENCH` show that SCPatch achieves state-of-the-art performance with **92.8% Pass@1** and **98.3% Pass@10**, outperforming frontier models like GPT-5.2 and Gemini-3-Flash.

---

## 🚀 Main Results

| Method | Pass@1 (%) | Pass@10 (%) | BLEU | Edit Sim | IR Sim |
| :--- | :---: | :---: | :---: | :---: | :---: |
| sGuard+ | 12.6 | - | 0.096 | 0.358 | - |
| GPT-5.2 | 83.2 | 95.4 | 0.422 | 0.615 | 0.661 |
| Gemini-3-Flash | 89.7 | 97.7 | 0.492 | 0.677 | 0.811 |
| Qwen3-Coder-Flash | 59.4 | 74.9 | 0.530 | 0.692 | 0.846 |
| **SCPatch (Ours)** | **92.8** | **98.3** | **0.443** | **0.639** | **0.866** |

*SCPatch simultaneously maximizes verification success and structural semantic preservation.*

---

## 🛠️ Environment Setup

### Prerequisites
- Python 3.9+
- NVIDIA GPUs (Experiments were conducted on 4x RTX 3090 24GB GPUs)

### 1. Install Python Dependencies
Clone the repository and install the required packages:
```bash
git clone https://github.com/Zhouonan/scpatch.git
cd scpatch
pip install -r requirements.txt
```

### 2. Install Verification Tools
SCPatch relies on external static analyzers for the multi-stage verification pipeline:
- **Solc-select**: For managing Solidity compiler versions.
  ```bash
  pip install solc-select
  ```
- **Slither** (v0.8.1): Pattern-based analysis.
  ```bash
  pip install slither-analyzer==0.8.1
  ```
- **Mythril** (v0.24.8): Symbolic analysis.
  ```bash
  pip install mythril==0.24.8
  ```

---

## 📂 Repository Structure

- `src/`: Core implementation of the SCPatch framework.
  - `src/ft_data_processing/`: Scope-aware context expansion and data preparation.
  - `src/tools/`: Integration of RAG (BM25, HNSW, MinHash) and verification tools (Slither, Mythril).
  - `src/fixing_pipeline.py`: Inference pipeline for vulnerability repair.
- `scripts/`: Scripts for executing the three training procedures.
  - `scripts/sft/`: SFT training scripts (LoRA adaptation).
  - `scripts/rl/`: Security-constrained RL (GRPO) training scripts.
- `data/`: Contains the `SCPATCH-BENCH` dataset (175 verified vulnerability-repair pairs).

---

## 💻 Usage

### Phase 1: Annotation & Data Preparation
Prepare the vulnerable code slices with scope-aware context expansion:
```bash
python src/annotation_pipeline.py --db_path path/to/smart_contracts.db
```

### Phase 2: Training (SFT + RL)
1. **Supervised Fine-Tuning (SFT)** on vulnerability-repair pairs using LoRA:
   ```bash
   bash scripts/sft/run_4gpu.sh
   ```
2. **Security-Constrained Policy Optimization (GRPO)** using the verifier feedback:
   ```bash
   bash scripts/rl/run_4gpu_rl_quick.sh
   ```

### Phase 3: Inference / Patch Generation
Generate and verify fixes for a target contract database using the trained model and multi-signal RAG:
```bash
python src/fixing_pipeline.py \
    --db_path path/to/smart_contracts.db \
    --model path/to/trained_scpatch_model
```

---

## 📊 SCPATCH-BENCH Dataset

We release `SCPATCH-BENCH`, a curated benchmark of 175 vulnerable functions spanning eight bug classes (Reentrancy, Access Control, Arithmetic, Unchecked Call, DoS, Timestamp Dependence, Bad Randomness, and Others). Each sample includes the vulnerable function, its enclosing context, the vulnerability type, and a verified ground-truth repair.

---

## 📝 Citation

If you find our work or dataset useful in your research, please consider citing our paper:

```bibtex
@article{zhang2025scpatch,
  title={SCPatch: Automated Smart Contract Vulnerability Repair via Security-Constrained Policy Optimization},
  author={Zhang, Weiye and Zhou, Nan and Liu, Zhenguang and Hou, Junxin and Fan, Shaojing and He, Qinming and Jiao, Yingying and Yang, Ziqi},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2025}
}
```

## 📜 License

This project is released under the [MIT License](LICENSE).
