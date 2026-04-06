#!/bin/bash
# 4卡分布式 + 低显存优化训练脚本
# 适用于显存紧张的情况 (如 OOM 错误)

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
        echo "✅ 训练脚本执行成功"
    else
        echo "❌ 训练脚本执行失败 (exit code: ${exit_code})"
    fi
}

trap on_exit EXIT

echo "🚀 启动 4卡分布式低显存训练..."
echo "==================================="

# bitsandbytes 会根据 BNB_CUDA_VERSION 强制选择 CUDA 版本；
# 如果你的系统/torch 是 CUDA 12.x，但这里被强制成 11.8，就会去找 libcudart.so.11.0 并报错。
if [[ -n "${BNB_CUDA_VERSION:-}" ]]; then
  echo "⚠️  检测到环境变量 BNB_CUDA_VERSION=${BNB_CUDA_VERSION}，为避免 CUDA 版本不匹配，已自动 unset"
  unset BNB_CUDA_VERSION
fi

# 先清理可能残留的显存
# nvidia-smi --gpu-reset 2>/dev/null || true

# 1. 显存分配优化 (解决碎片化问题)
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

# 2. 设置可见 GPU
export CUDA_VISIBLE_DEVICES=0,1,2,3

# 3. 启动命令
# 关键参数调整：
# --batch_size 2: 极大降低单卡显存压力
# --gradient_accumulation 8: 补偿 Batch Size，总批次 = 2 * 8 * 4(GPUs) = 64
# --gradient_checkpointing: 代码中已开启，用计算换显存
accelerate launch \
    --multi_gpu \
    --num_processes=4 \
    --mixed_precision=fp16 \
    scripts/sft/train_lora.py \
    --train_data data/processed/fix_sft/1227.func_only_over2048.codeblock/sft.jsonl \
    --val_data data/processed/fix_sft/1227.func_only_over2048.codeblock/val.jsonl \
    --model_path /home/user/zn/models_cache/Qwen2.5-7B-Instruct \
    --output_dir models/qwen2.5-7b/fix_sft/1229 \
    --batch_size 1 \
    --gradient_accumulation 8 \
    --learning_rate 5e-5 \
    --warmup_steps 2 \
    --lora_r 16 \
    --lora_alpha 32 \
    --lora_dropout 0.05 \
    --epochs 2 \
    --fp16 \
    --device cuda \
    --quantization 8bit \
    --prompt_format chat --auto_output_subdir \
    # --alpha_copy 0.1 \
    # --beta_struct 0.1 \

