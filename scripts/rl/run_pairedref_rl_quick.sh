#!/bin/bash
# Paired-ref RL-LoRA quick launcher
#
# Supports:
# - NUM_PROCESSES=2:  rank0 policy on GPU0, rank1 ref on GPU1
# - NUM_PROCESSES=4:  rank0/1 policy on GPU0/1, rank2/3 ref on GPU2/3
#
# This script does NOT modify the existing run_4gpu_rl_quick.sh (kept for the original workflow).

set -euo pipefail

START_TS="$(date +%s)"
START_STR="$(date '+%F %T')"

format_duration() {
  local total="$1"
  local h=$((total / 3600))
  local m=$(((total % 3600) / 60))
  local s=$((total % 60))
  printf "%02d:%02d:%02d" "$h" "$m" "$s"
}

on_exit() {
  local exit_code="$?"
  local end_ts end_str elapsed
  end_ts="$(date +%s)"
  end_str="$(date '+%F %T')"
  elapsed="$((end_ts - START_TS))"

  echo ""
  echo "==================================="
  echo "开始时间: ${START_STR}"
  echo "结束时间: ${end_str}"
  echo "运行耗时: $(format_duration "${elapsed}") (${elapsed}s)"

  if [[ "${exit_code}" -eq 0 ]]; then
    echo "✅ Paired-ref RL 训练执行成功"
  else
    echo "❌ Paired-ref RL 训练执行失败 (exit code: ${exit_code})"
  fi
}

trap on_exit EXIT

# Avoid bitsandbytes forcing mismatched CUDA
if [[ -n "${BNB_CUDA_VERSION:-}" ]]; then
  echo "⚠️  检测到环境变量 BNB_CUDA_VERSION=${BNB_CUDA_VERSION}，已自动 unset"
  unset BNB_CUDA_VERSION
fi

export TMPDIR="${TMPDIR:-/dev/shm}"
export PYTORCH_ALLOC_CONF="${PYTORCH_ALLOC_CONF:-expandable_segments:True}"

NUM_PROCESSES="${NUM_PROCESSES:-2}"   # 2 or 4
if [[ "${NUM_PROCESSES}" != "2" && "${NUM_PROCESSES}" != "4" ]]; then
  echo "NUM_PROCESSES must be 2 or 4, got: ${NUM_PROCESSES}"
  exit 1
fi

if [[ "${NUM_PROCESSES}" == "2" ]]; then
  export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0,1}"
else
  export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0,1,2,3}"
fi

TRAIN_JSONL="${TRAIN_JSONL:-data/processed/fix_sft/1227.func_only_over2048.codeblock/rl.jsonl}"
BASE_MODEL="${BASE_MODEL:-../models_cache/Qwen2.5-7B-Instruct}"
SFT_LORA="${SFT_LORA:-results/rl_lora_pairedref_0130_step150_p100_1229-051829/rl_lora}"
OUT_DIR="${OUT_DIR:-results/rl_lora_pairedref_0202_step250_p200_1229-051829}"

LIMIT="${LIMIT:-3000}"
K="${K:-4}"
STEPS="${STEPS:-200}"
BATCH_PROMPTS="${BATCH_PROMPTS:-1}"
LR="${LR:-2e-5}"

echo "🚀 启动 Paired-ref RL-LoRA..."
echo "==================================="
echo "CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES}"
echo "NUM_PROCESSES=${NUM_PROCESSES}"

accelerate launch \
  --multi_gpu \
  --num_processes="${NUM_PROCESSES}" \
  --mixed_precision=fp16 \
  scripts/rl/train_lora_grpo_pairedref.py \
  --ref-mode paired \
  --train-jsonl "${TRAIN_JSONL}" \
  --limit "${LIMIT}" \
  --base-model "${BASE_MODEL}" \
  --sft-lora "${SFT_LORA}" \
  --k "${K}" \
  --steps "${STEPS}" \
  --batch-prompts "${BATCH_PROMPTS}" \
  --lr "${LR}" \
  --out-dir "${OUT_DIR}" \
  --prompt-format chat \
  --use-db-contract \
  --db-path sqlite:///smart_contracts.db \
  --dtype bf16 \
  --gradient-checkpointing \
  --epsilon-cost 0.5 \
  --lambda-lr 0.01 \
  --grad-accum 2 \
  --lambda-init 0 \
  --gen-microbatch 4 \
  --seed 1 \
  --mythril \
  --rag-mode gate \
  --rag-index-path results/rag_index_1228 \
  --rag-build-from-jsonl /home/user/zn/smart_contract_vulnerability_detection/data/processed/fix_sft/1227.func_only_over2048.codeblock/sft.jsonl \
  --rag-build-limit 2000 \
  --max-orig-sim 0.995 \
  "$@"

