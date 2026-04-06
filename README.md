# SCPatch: Smart Contract Vulnerability Patching with LLM and RAG

SCPatch is an automated framework for smart contract vulnerability patching, leveraging Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG). It provides a systematic pipeline for annotating vulnerabilities and generating verifiable fixes.

## Project Overview

SCPatch operates in two main phases:
1.  **Annotation Pipeline**: Automatically analyzes and labels vulnerabilities within smart contract source code.
2.  **Fixing Pipeline**: Generates high-quality patches using LLMs, assisted by RAG to retrieve relevant fixing patterns.

The framework integrates with industry-standard analysis tools like **Mythril** and **Slither** to validate generated fixes.

## Features

- **Multi-tool Integration**: Uses Slither and Mythril for vulnerability detection and verification.
- **RAG-Enhanced Patching**: Utilizes a vector database to provide relevant fixing examples to the LLM.
- **Modular Design**: Easy to extend with new models, datasets, or analysis tools.
- **End-to-End Pipeline**: From raw contract code to verified patches.

## Installation

### Prerequisites
- Python 3.9+
- [Solc-select](https://github.com/crytic/solc-select) (for managing Solidity compiler versions)
- [Slither](https://github.com/crytic/slither)
- [Mythril](https://github.com/Consensys/mythril)

### Setup
1.  Clone the repository:
    ```bash
    git clone https://github.com/Zhouonan/scpatch.git
    cd scpatch
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Phase 1: Annotation
Annotate the smart contracts in the database:
```bash
python src/annotation_pipeline.py --db_path path/to/your/database.db
```

### Phase 2: Patching
Generate and verify fixes:
```bash
python src/fixing_pipeline.py --db_path path/to/your/database.db --model path/to/model
```

## Project Structure
- `src/`: Core implementation of the pipelines and tools.
- `scripts/`: Data processing, training (SFT/RL), and evaluation scripts.
- `requirements.txt`: Python dependency list.

## License
This project is for research purposes.
