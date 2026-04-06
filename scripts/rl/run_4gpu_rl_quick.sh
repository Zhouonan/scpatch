#!/bin/bash
# 4卡分布式（Accelerate）快速验证版 RL-LoRA 训练脚本
# - 多进程：每张卡处理不同 prompts 分片，梯度同步更新 LoRA
# - 验证：solc + Slither（不含 Mythril）
#
# 运行前请确认：
# - 已安装/可用: accelerate, transformers, peft, slither-analyzer, py-solc-x, solc/solcx
# - base model 路径、SFT LoRA 路径正确
#
# 示例：
#   bash smart_contract_vulnerability_detection/scripts/rl/run_4gpu_rl_quick.sh

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
  echo "⏱️  开始时间: ${START_STR}"
  echo "⏱️  结束时间: ${end_str}"
  echo "⏱️  运行耗时: $(format_duration "${elapsed}") (${elapsed}s)"

  if [[ "${exit_code}" -eq 0 ]]; then
    echo "✅ RL 训练脚本执行成功"
  else
    echo "❌ RL 训练脚本执行失败 (exit code: ${exit_code})"
  fi
}

trap on_exit EXIT

echo "🚀 启动 4卡分布式 RL-LoRA 快速训练..."
echo "==================================="

# bitsandbytes 会根据 BNB_CUDA_VERSION 强制选择 CUDA 版本；
# 若系统/torch 实际是 CUDA 12.x，但被强制为 11.8，会触发 libcudart.so.11.0 缺失报错。
if [[ -n "${BNB_CUDA_VERSION:-}" ]]; then
  echo "⚠️  检测到环境变量 BNB_CUDA_VERSION=${BNB_CUDA_VERSION}，为避免 CUDA 版本不匹配，已自动 unset"
  unset BNB_CUDA_VERSION
fi

# 利用内存盘 (Ramdisk) 优化 IO
export TMPDIR=/dev/shm

# 1) 显存分配优化（缓解碎片化）
export PYTORCH_ALLOC_CONF=expandable_segments:True

# 2) 设置可见 GPU
export CUDA_VISIBLE_DEVICES=0,1

# 3) 可配置路径（按需修改）
TRAIN_JSONL="${TRAIN_JSONL:-data/processed/fix_sft/1211/train.jsonl}"
BASE_MODEL="${BASE_MODEL:-../models_cache/Qwen2.5-7B-Instruct}"
SFT_LORA="${SFT_LORA:-results/rl_lora_1218_1/rl_lora}"
OUT_DIR="${OUT_DIR:-results/rl_lora_1218_2}"

# 4) 训练超参（快速验证）
LIMIT="${LIMIT:-400}"
K="${K:-4}"
STEPS="${STEPS:-100}"
BATCH_PROMPTS="${BATCH_PROMPTS:-1}"  # 每卡每步处理的 prompt 数；验证很慢，建议先 1
LR="${LR:-1e-5}"

accelerate launch \
  --multi_gpu \
  --num_processes=2 \
  --mixed_precision=fp16 \
  scripts/rl/train_lora_grpo_quick.py \
  --stagger-load \
  --stagger-load-group-size 1 \
  --stagger-load-sleep 0.2 \
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
  --ref-on-cpu\
  --dtype bf16 \
  --gradient-checkpointing \
  --prompt-format chat --epsilon-cost 1 --lambda-lr 0.02 --grad-accum 2 --lambda-init 1.0 --debug-verify
