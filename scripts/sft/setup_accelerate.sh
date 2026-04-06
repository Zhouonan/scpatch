#!/bin/bash
# 快速配置accelerate的脚本

echo "配置Accelerate用于4x RTX 3090多GPU训练..."

# 创建加速配置
cat > ~/.cache/huggingface/accelerate/default_config.yaml << EOF
compute_environment: LOCAL_MACHINE
distributed_type: MULTI_GPU
downcast_bf16: 'no'
gpu_ids: all
machine_rank: 0
main_training_function: main
mixed_precision: fp16
num_machines: 1
num_processes: 4
rdzv_backend: static
same_network: true
tpu_env: []
tpu_use_cluster: false
tpu_use_sudo: false
use_cpu: false
EOF

echo "✅ Accelerate配置完成！"
echo ""
echo "配置详情:"
cat ~/.cache/huggingface/accelerate/default_config.yaml
echo ""
echo "现在可以使用以下命令进行多GPU训练:"
echo "  accelerate launch scripts/train_lora.py ..."
echo "或者:"
echo "  bash scripts/run_lora_train_multi_gpu.sh"

