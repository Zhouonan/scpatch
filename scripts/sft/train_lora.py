\
\
\
   

import os
import sys
import json
import argparse
import re
import time
import hashlib
from datetime import datetime
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
    get_linear_schedule_with_warmup
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    TaskType
)
from typing import Dict, List, Optional
import numpy as np
from tqdm import tqdm
import wandb

        
_this_file = os.path.abspath(__file__)
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(_this_file)))                                              
_scripts_root = os.path.dirname(os.path.dirname(_this_file))                                                      
for _p in (_project_root, _scripts_root):
    if _p not in sys.path:
        sys.path.append(_p)

try:
    from src.training.auxiliary_losses import (
        CopyMechanismHead,
        ContrastiveStructuralLoss,
        compute_copy_labels,
    )
except Exception:
    CopyMechanismHead = None
    ContrastiveStructuralLoss = None
    compute_copy_labels = None


def _sanitize_for_path(s: str, max_len: int = 80) -> str:
                                                  
    s = str(s)
    s = s.strip().replace(" ", "_")
    s = s.replace(os.sep, "-")
                                             
    s = re.sub(r"[^A-Za-z0-9._+=-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-._")
    if not s:
        s = "run"
    return s[:max_len]


def _jsonable(obj):
                                                                                 
    try:
        json.dumps(obj)
        return obj
    except Exception:
        pass
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return str(obj)


def _build_run_name(args: argparse.Namespace) -> str:
    model_tag = args.model_name
                              
    if os.path.exists(model_tag):
        model_tag = os.path.basename(os.path.normpath(model_tag))
    else:
        model_tag = model_tag.split("/")[-1]

    parts = [
        _sanitize_for_path(model_tag, 40),
        f"lora_r{args.lora_r}",
        f"a{args.lora_alpha}",
        f"d{args.lora_dropout}",
        f"lr{args.learning_rate}",
        f"bs{args.batch_size}",
        f"ga{args.gradient_accumulation}",
        f"ep{args.epochs}",
        f"q{args.quantization}",
        f"pf{args.prompt_format}",
    ]
    if getattr(args, "alpha_copy", 0.0):
        parts.append(f"ac{args.alpha_copy}")
    if getattr(args, "beta_struct", 0.0):
        parts.append(f"bsx{args.beta_struct}")

    ts = datetime.now().strftime("%m%d-%H%M%S")
    name = _sanitize_for_path("-".join(parts), 180)
    return f"{name}-{ts}"


def _get_dist_info():
\
\
\
       
              
    rank = int(os.environ.get("RANK", os.environ.get("ACCELERATE_PROCESS_INDEX", 0)))
    local_rank = int(os.environ.get("LOCAL_RANK", os.environ.get("ACCELERATE_LOCAL_PROCESS_INDEX", 0)))
    world_size = int(os.environ.get("WORLD_SIZE", os.environ.get("ACCELERATE_NUM_PROCESSES", 1)))
    return rank, local_rank, world_size


def _run_session_key(args: argparse.Namespace) -> str:
\
\
\
       
    fields = {
        "model_name": getattr(args, "model_name", None),
        "model_path": getattr(args, "model_path", None),
        "train_data": getattr(args, "train_data", None),
        "val_data": getattr(args, "val_data", None),
        "output_dir_base": getattr(args, "output_dir", None),
        "run_name": getattr(args, "run_name", None),
        "auto_output_subdir": bool(getattr(args, "auto_output_subdir", False)),
        "lora_r": getattr(args, "lora_r", None),
        "lora_alpha": getattr(args, "lora_alpha", None),
        "lora_dropout": getattr(args, "lora_dropout", None),
        "epochs": getattr(args, "epochs", None),
        "batch_size": getattr(args, "batch_size", None),
        "gradient_accumulation": getattr(args, "gradient_accumulation", None),
        "learning_rate": getattr(args, "learning_rate", None),
        "warmup_steps": getattr(args, "warmup_steps", None),
        "quantization": getattr(args, "quantization", None),
        "prompt_format": getattr(args, "prompt_format", None),
        "alpha_copy": getattr(args, "alpha_copy", None),
        "beta_struct": getattr(args, "beta_struct", None),
        "struct_temperature": getattr(args, "struct_temperature", None),
    }
    payload = json.dumps(fields, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _wait_for_file(path: str, timeout_s: float = 600.0, poll_s: float = 0.2) -> None:
                                                                             
    deadline = time.time() + float(timeout_s)
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(float(poll_s))
    raise TimeoutError(f"Timed out waiting for file: {path}")


class AuxLossTrainer(Trainer):
\
\
\
       

    def __init__(self, *args, alpha_copy: float = 0.0, beta_struct: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.alpha_copy = float(alpha_copy)
        self.beta_struct = float(beta_struct)

    @staticmethod
    def _infer_split_points(labels: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
\
\
\
\
           
                                                          
        valid = attention_mask.to(dtype=torch.bool)
        is_resp = (labels != -100) & valid
        bsz, seqlen = labels.shape
        idxs = torch.arange(seqlen, device=labels.device).unsqueeze(0).expand(bsz, -1)
                                                       
        split = idxs.masked_fill(~is_resp, seqlen).min(dim=1).values
        return split

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
                                                             
        outputs = model(
            input_ids=inputs.get("input_ids"),
            attention_mask=inputs.get("attention_mask"),
            labels=inputs.get("labels"),
            output_hidden_states=(self.alpha_copy > 0 or self.beta_struct > 0),
            return_dict=True,
        )
        lm_loss = outputs.loss

        if (self.alpha_copy <= 0 and self.beta_struct <= 0) or not hasattr(outputs, "hidden_states"):
            return (lm_loss, outputs) if return_outputs else lm_loss

        hidden_states = outputs.hidden_states[-1]             
        input_ids = inputs["input_ids"]
        attention_mask = inputs.get("attention_mask", torch.ones_like(input_ids))
        labels = inputs["labels"]

        split_points = self._infer_split_points(labels, attention_mask)
        bsz, seqlen = input_ids.shape

                                                                       
        idxs = torch.arange(seqlen, device=input_ids.device).unsqueeze(0).expand(bsz, -1)
        valid = attention_mask.to(dtype=torch.bool)
        input_mask = (idxs < split_points.unsqueeze(1)) & valid
        output_mask = (idxs >= split_points.unsqueeze(1)) & valid & (labels != -100)

        copy_loss = torch.tensor(0.0, device=lm_loss.device)
        struct_loss = torch.tensor(0.0, device=lm_loss.device)

                                                                                     
        if self.alpha_copy > 0 and hasattr(model, "copy_head") and compute_copy_labels is not None:
            per_sample = []
            pad_id = getattr(getattr(model, "config", None), "pad_token_id", None)
            for b in range(bsz):
                split_b = int(split_points[b].item())
                                                  
                attn_len = int(attention_mask[b].sum().item()) if attention_mask is not None else seqlen
                split_b = max(0, min(split_b, attn_len))
                src_ids = input_ids[b, :split_b]
                tgt_ids = input_ids[b, split_b:attn_len]
                if tgt_ids.numel() == 0 or src_ids.numel() == 0:
                    continue

                                                             
                tgt_mask = output_mask[b, split_b:attn_len]
                copy_labels = compute_copy_labels(
                    src_ids,
                    tgt_ids,
                    output_mask=tgt_mask.unsqueeze(0),
                    ignore_token_id=pad_id,
                )

                enc_h = hidden_states[b : b + 1, :split_b, :]
                dec_h = hidden_states[b : b + 1, split_b:attn_len, :]
                per_sample.append(model.copy_head(dec_h, enc_h, copy_labels.to(device=dec_h.device)))

            if per_sample:
                copy_loss = torch.stack(per_sample).mean()

                                                                                 
        if self.beta_struct > 0 and hasattr(model, "contrastive_loss_fn"):
            struct_loss = model.contrastive_loss_fn(
                hidden_states,
                hidden_states,
                input_mask.to(dtype=torch.long),
                output_mask.to(dtype=torch.long),
            )

        total_loss = lm_loss + self.alpha_copy * copy_loss + self.beta_struct * struct_loss
        return (total_loss, outputs) if return_outputs else total_loss


class VulnerabilityDataset(Dataset):
                     
    
    def __init__(
        self,
        data_path: str,
        tokenizer,
        max_length: int = 2048,
        prompt_template: str = None,
        prompt_format: str = "plain"
    ):
\
\
\
\
\
\
\
\
           
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.prompt_format = prompt_format

                                                                                                      
        try:
            self.tokenizer.truncation_side = "left"
        except Exception:
            pass
        
                 
        if prompt_template is None:
            self.prompt_template = (
                "Below is an instruction that describes a task, paired with an input that provides further context. "
                "Write a response that appropriately completes the request.\n\n"
                "### Instruction:\n{instruction}\n\n"
                "### Input:\n{input}\n\n"
                "### Response:\n{output}"
            )
        else:
            self.prompt_template = prompt_template
        
              
        self.data = self._load_data(data_path)
        print(f"Loaded {len(self.data)} samples from {data_path}")
    
    def _load_data(self, data_path: str) -> List[Dict]:
                       
        data = []
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                item = json.loads(line.strip())
                data.append(item)
        return data
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
                    
        item = self.data[idx]

        instruction = item.get('instruction', '')
        input_text = item.get('input', '')
        output_text = item.get('output', '')

               
        if self.prompt_format in ("chat", "auto") and hasattr(self.tokenizer, "apply_chat_template"):
            user_content = input_text
            messages_full = [
                {"role": "system", "content": instruction},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": output_text},
            ]
            prompt = self.tokenizer.apply_chat_template(messages_full, tokenize=False, add_generation_prompt=False)

                                                                  
            messages_prefix = [
                {"role": "system", "content": instruction},
                {"role": "user", "content": user_content},
            ]
            prefix = self.tokenizer.apply_chat_template(messages_prefix, tokenize=False, add_generation_prompt=True)
        else:
            prompt = self.prompt_template.format(
                instruction=instruction,
                input=input_text,
                output=output_text
            )
            prefix = prompt.split("### Response:")[0] + "### Response:\n"
        
               
                                                                                                   
                                                                                                    
                                                                                                    
                                                          

                                                                                          
                                                                                                              
        try:
            full_len = len(self.tokenizer(prompt, add_special_tokens=False)['input_ids'])
            prefix_len = len(self.tokenizer(prefix, add_special_tokens=False)['input_ids'])
        except Exception:
            full_len = None
            prefix_len = None

                                                
        tokenized = self.tokenizer(
            prompt,
            max_length=self.max_length,
            truncation=True,
            padding='max_length',
            return_tensors='pt',
            add_special_tokens=False,
        )
        
                        
        labels = tokenized['input_ids'].clone()
        
                                                                              
                                                                     
        try:
            if full_len is not None and prefix_len is not None:
                overflow = max(0, int(full_len) - int(self.max_length))                                  
                response_token_start = int(prefix_len) - overflow
            else:
                                                           
                response_token_start = len(self.tokenizer(prefix, add_special_tokens=False)['input_ids'])

            response_token_start = max(0, min(int(response_token_start), labels.shape[1]))
            labels[0, :response_token_start] = -100            
        except Exception:
            pass

                                                                
        try:
            if 'attention_mask' in tokenized:
                labels[tokenized['attention_mask'] == 0] = -100
        except Exception:
            pass
        
        return {
            'input_ids': tokenized['input_ids'].squeeze(),
            'attention_mask': tokenized['attention_mask'].squeeze(),
            'labels': labels.squeeze()
        }


class LoRATrainer:
                   
    
    def __init__(
        self,
        model_name: str = "deepseek-ai/deepseek-coder-6.7b-base",
        lora_config: Dict = None,
        training_args: Dict = None,
        quantization: str = "8bit",
        device: str = "cuda"
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
           
        self.device = device
        self.model_name = model_name
        self.quantization = quantization
        
                  
        if lora_config is None:
            lora_config = {
                'r': 8,         
                'lora_alpha': 32,            
                                                                      
                'target_modules': ['q_proj', 'v_proj', 'k_proj', 'o_proj', 'gate_proj', 'up_proj', 'down_proj'],
                'lora_dropout': 0.05,
                'bias': 'none',
                'task_type': TaskType.CAUSAL_LM
            }
        
        self.lora_config = lora_config
        
                
        if training_args is None:
            training_args = {
                'output_dir': './checkpoints',
                'num_train_epochs': 3,
                'per_device_train_batch_size': 4,
                'per_device_eval_batch_size': 4,
                'gradient_accumulation_steps': 4,
                'learning_rate': 2e-4,
                'warmup_steps': 100,
                'logging_steps': 10,
                'save_steps': 500,
                'eval_steps': 500,
                'save_total_limit': 3,
                'fp16': True,
                'eval_strategy': 'steps',                     
                'load_best_model_at_end': True,
                'report_to': 'wandb'
            }
        
        self.training_args = training_args
        
                  
        print("Loading tokenizer and model...")
        self._load_model_and_tokenizer()
        
                
        print("Configuring LoRA...")
        self._setup_lora()
    
    def _load_model_and_tokenizer(self):
                      
        import os
        
                   
        is_local = os.path.exists(self.model_name)
        
        try:
                   
            print(f"Loading tokenizer from: {self.model_name}")
            
                            
            tokenizer_kwargs = {
                "trust_remote_code": True,
                "padding_side": 'right',
                "use_fast": True
            }
            
                    
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name, **tokenizer_kwargs)
            except ValueError as e:
                if "Qwen2Tokenizer" in str(e):
                    print("⚠️  AutoTokenizer failed to recognize Qwen2Tokenizer, trying generic loading...")
                                                               
                    from transformers import Qwen2TokenizerFast
                    self.tokenizer = Qwen2TokenizerFast.from_pretrained(self.model_name, **tokenizer_kwargs)
                else:
                    raise e
            
            print("✅ Tokenizer loaded successfully")
            
        except Exception as e:
            print(f"❌ Error loading tokenizer: {str(e)}")
            if is_local:
                print("\n💡 尝试回退到 slow tokenizer...")
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(
                        self.model_name,
                        trust_remote_code=True,
                        padding_side='right',
                        use_fast=False
                    )
                    print("✅ Slow tokenizer loaded successfully")
                except Exception as e2:
                    print(f"❌ Slow tokenizer also failed: {str(e2)}")
                    raise e
            
        except Exception as e:
            print(f"❌ Error loading tokenizer: {str(e)}")
            if is_local:
                print("\n💡 本地模型加载失败，可能的原因：")
                print("  1. 模型文件不完整（缺少tokenizer文件）")
                print("  2. transformers版本不兼容")
                print("  3. config.json格式有问题")
                print("\n解决方案：")
                print("  1. 检查模型目录是否包含以下文件：")
                print("     - config.json")
                print("     - tokenizer.json 或 tokenizer_config.json")
                print("     - vocab.json / merges.txt")
                print("  2. 尝试使用 HuggingFace 模型名重新下载")
            raise
        
                     
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
            print(f"Set pad_token to eos_token: {self.tokenizer.eos_token}")
        
        try:
                                 
            print(f"\nLoading model from: {self.model_name}")
            
                                   
            local_rank = int(os.environ.get("LOCAL_RANK", 0))
            world_size = int(os.environ.get("WORLD_SIZE", 1))
            
            print(f"Process info: local_rank={local_rank}, world_size={world_size}")

            extra_model_kwargs = {}
            quant_mode = (self.quantization or "8bit").lower()
            if quant_mode not in {"8bit", "none"}:
                raise ValueError(f"Unsupported quantization mode: {self.quantization}. Use '8bit' or 'none'.")

            if quant_mode == "8bit":
                try:
                    from transformers import BitsAndBytesConfig
                    bnb_config = BitsAndBytesConfig(
                        load_in_8bit=True,
                        llm_int8_threshold=6.0,
                        llm_int8_has_fp16_weight=False
                    )
                    extra_model_kwargs["quantization_config"] = bnb_config
                except Exception as bnb_e:
                    print("❌ bitsandbytes 8bit 量化初始化失败（通常是 CUDA 运行时库缺失/版本不匹配）")
                    print(f"   具体错误: {str(bnb_e)}")
                    print("   你可以尝试：")
                    print("   1) 先取消环境变量强制版本：unset BNB_CUDA_VERSION")
                    print("   2) 或在当前 conda 环境安装 CUDA 11.8 runtime（确保有 libcudart.so.11.0）")
                    print("   3) 或临时不用量化跑通：在命令里加 --quantization none（可能更吃显存）")
                    raise

                                 
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                trust_remote_code=True,
                **extra_model_kwargs,
                device_map={"": local_rank},                             
                torch_dtype=torch.float16,
                low_cpu_mem_usage=True
            )
            print(f"✅ Model loaded successfully on GPU {local_rank}")
            
        except Exception as e:
            print(f"❌ Error loading model: {str(e)}")
            if is_local:
                print("\n💡 本地模型加载失败，可能的原因：")
                print("  1. 模型权重文件损坏或不完整")
                print("  2. 显存不足")
                print("  3. 模型格式不兼容")
            raise
        
                  
        self.model = prepare_model_for_kbit_training(self.model)
        
                
        param_count = sum(p.numel() for p in self.model.parameters())
        trainable_params = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
        
        print(f"\n{'='*50}")
        print(f"Model Information:")
        print(f"  Model name: {self.model_name}")
        print(f"  Total parameters: {param_count:,} ({param_count/1e9:.2f}B)")
        print(f"  Trainable parameters (before LoRA): {trainable_params:,}")
        print(f"{'='*50}\n")
    
    def _setup_lora(self):
                    
                  
        peft_config = LoraConfig(**self.lora_config)
        
                
        self.model = get_peft_model(self.model, peft_config)
        
                 
        self.model.print_trainable_parameters()
    
    def train(
        self,
        train_data_path: str,
        val_data_path: Optional[str] = None,
        output_dir: str = './lora_model',
        wandb_project: Optional[str] = None,
        prompt_format: str = "plain",
        max_length: int = 2048,
        alpha_copy: float = 0.0,
        beta_struct: float = 0.0,
        struct_temperature: float = 0.07,
    ):
\
\
\
\
\
\
\
\
           
                                           
        rank, _, _ = _get_dist_info()
        if wandb_project:
            if rank == 0:
                wandb.init(project=wandb_project, name='lora-vulnerability-detection')
            else:
                                                                             
                os.environ.setdefault("WANDB_DISABLED", "true")
        
               
        print("Loading datasets...")
        train_dataset = VulnerabilityDataset(
            train_data_path,
            self.tokenizer,
            max_length=int(max_length),
            prompt_format=prompt_format,
        )
        
        val_dataset = None
        if val_data_path:
            val_dataset = VulnerabilityDataset(
                val_data_path,
                self.tokenizer,
                max_length=int(max_length),
                prompt_format=prompt_format
            )
        
               
        data_collator = DataCollatorForSeq2Seq(
            self.tokenizer,
            model=self.model,
            padding=True
        )
        
              
        training_args = TrainingArguments(
            output_dir=output_dir,
            **self.training_args
        )

                                                                                                     
        use_aux = (alpha_copy and alpha_copy > 0) or (beta_struct and beta_struct > 0)
        if use_aux:
            if CopyMechanismHead is None or ContrastiveStructuralLoss is None:
                raise RuntimeError(
                    "Aux losses requested but src.training.auxiliary_losses is not available."
                )
            hidden_size = getattr(self.model.config, "hidden_size", None)
            if hidden_size is None:
                raise RuntimeError("Model config.hidden_size not found; cannot init auxiliary losses.")

                                                                           
            model_device = next(self.model.parameters()).device
            self.model.copy_head = CopyMechanismHead(hidden_size).to(model_device)
            self.model.contrastive_loss_fn = ContrastiveStructuralLoss(
                hidden_size,
                temperature=float(struct_temperature),
            ).to(model_device)
        
               
        trainer_cls = AuxLossTrainer if use_aux else Trainer
        trainer_kwargs = dict(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            data_collator=data_collator,
        )
        if use_aux:
            trainer_kwargs.update(alpha_copy=float(alpha_copy), beta_struct=float(beta_struct))
        trainer = trainer_cls(**trainer_kwargs)
        
              
        print("Starting training...")
        trainer.train()
        
                
        if trainer.is_world_process_zero():
            print(f"Saving final model to {output_dir}")
            trainer.save_model(output_dir)
            self.tokenizer.save_pretrained(output_dir)

                                                                       
        if trainer.is_world_process_zero():
            try:
                run_cfg = {
                    "model_name": self.model_name,
                    "quantization": self.quantization,
                    "train_data_path": train_data_path,
                    "val_data_path": val_data_path,
                    "output_dir": output_dir,
                    "prompt_format": prompt_format,
                    "max_length": int(max_length),
                    "lora_config": _jsonable(self.lora_config),
                    "training_args_dict": _jsonable(self.training_args),
                    "hf_training_args": json.loads(training_args.to_json_string()),
                    "aux_losses": {
                        "alpha_copy": float(alpha_copy),
                        "beta_struct": float(beta_struct),
                        "struct_temperature": float(struct_temperature),
                    },
                }
                with open(os.path.join(output_dir, "run_config.json"), "w", encoding="utf-8") as f:
                    json.dump(run_cfg, f, ensure_ascii=False, indent=2)
            except Exception as e:
                print(f"⚠️  Failed to write run_config.json: {e}")
        
        print("Training completed!")
    
    def inference(
        self,
        instruction: str,
        input_text: str,
        max_new_tokens: int = 512,
        temperature: float = 0.7,
        top_p: float = 0.9
    ) -> str:
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
\
           
               
        prompt = (
            "Below is an instruction that describes a task, paired with an input that provides further context. "
            "Write a response that appropriately completes the request.\n\n"
            f"### Instruction:\n{instruction}\n\n"
            f"### Input:\n{input_text}\n\n"
            "### Response:\n"
        )
        
            
        inputs = self.tokenizer(
            prompt,
            return_tensors='pt',
            truncation=True,
            max_length=2048
        ).to(self.device)
        
            
        self.model.eval()
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                top_p=top_p,
                do_sample=True,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id
            )
        
            
        response = self.tokenizer.decode(
            outputs[0][inputs['input_ids'].shape[1]:],
            skip_special_tokens=True
        )
        
        return response.strip()


def main():
             
    parser = argparse.ArgumentParser(
        description='LoRA微调脚本 - 智能合约漏洞检测'
    )
    
          
    parser.add_argument(
        '--train_data',
        type=str,
        required=True,
        help='训练数据路径（JSONL格式）'
    )
    parser.add_argument(
        '--val_data',
        type=str,
        default=None,
        help='验证数据路径（JSONL格式）'
    )
    parser.add_argument(
        '--max_length',
        type=int,
        default=2048,
        help='最大序列长度（越小越省显存；建议 OOM 时降到 1024/1536）'
    )
    
          
    parser.add_argument(
        '--model_name',
        type=str,
        default='deepseek-ai/deepseek-coder-6.7b-base',
        help='基座模型名称或本地路径 (支持HuggingFace模型名或本地目录路径)'
    )
    parser.add_argument(
        '--model_path',
        type=str,
        default=None,
        help='本地模型路径（如果指定，将覆盖model_name）'
    )
    parser.add_argument(
        '--output_dir',
        type=str,
        default='./lora_model',
        help='输出目录'
    )
    parser.add_argument(
        '--run_name',
        type=str,
        default=None,
        help='可选：手动指定本次运行的子目录名（会被拼到 output_dir 下面）'
    )
    parser.add_argument(
        '--auto_output_subdir',
        action='store_true',
        help='可选：自动用主要超参生成子目录名，并输出到你提供的 output_dir/<run_name>/ 下'
    )
    
            
    parser.add_argument('--lora_r', type=int, default=8, help='LoRA秩')
    parser.add_argument('--lora_alpha', type=int, default=32, help='LoRA alpha')
    parser.add_argument('--lora_dropout', type=float, default=0.05, help='LoRA dropout')
    
          
    parser.add_argument('--epochs', type=int, default=3, help='训练轮数')
    parser.add_argument('--batch_size', type=int, default=4, help='批次大小')
    parser.add_argument('--gradient_accumulation', type=int, default=4, help='梯度累积步数')
    parser.add_argument('--learning_rate', type=float, default=2e-4, help='学习率')
    parser.add_argument('--warmup_steps', type=int, default=100, help='预热步数')
    
          
    parser.add_argument('--device', type=str, default='cuda', help='训练设备')
    parser.add_argument('--wandb_project', type=str, default=None, help='W&B项目名称')
    parser.add_argument('--fp16', action='store_true', help='使用FP16混合精度')
    parser.add_argument(
        '--quantization',
        type=str,
        default='8bit',
        choices=['8bit', 'none'],
        help="模型加载量化方式：'8bit'（默认，省显存但依赖 bitsandbytes + CUDA 运行时库）或 'none'（不量化）",
    )
    parser.add_argument(
        '--prompt_format',
        type=str,
        default='plain',
        choices=['plain', 'chat', 'auto'],
        help="Prompt format. For Qwen2.5-Instruct prefer 'chat' (uses tokenizer.apply_chat_template).",
    )

                                 
    parser.add_argument('--alpha_copy', type=float, default=0.0, help='Weight for copy mechanism loss (0 disables).')
    parser.add_argument('--beta_struct', type=float, default=0.0, help='Weight for contrastive structural loss (0 disables).')
    parser.add_argument('--struct_temperature', type=float, default=0.07, help='Temperature for structural contrastive loss.')
    
    args = parser.parse_args()

                                              
    rank, local_rank, world_size = _get_dist_info()
    is_distributed = world_size > 1

                                                                                   
                                                                      
    _devnull = None
    if is_distributed and rank != 0:
        try:
            _devnull = open(os.devnull, "w")
            sys.stdout = _devnull
        except Exception:
            pass
        try:
            from transformers.utils import logging as hf_logging
            hf_logging.set_verbosity_error()
        except Exception:
            pass
    
               
    if args.device == 'cuda' and not torch.cuda.is_available():
        print("Warning: CUDA not available, falling back to CPU")
        args.device = 'cpu'
        args.quantization = 'none'
    
                            
    if args.model_path:
        args.model_name = args.model_path
        print(f"✅ 使用本地模型: {args.model_path}")
    
                                                                          
                                                                                          
    output_dir_base = os.path.abspath(args.output_dir)
    if args.run_name or args.auto_output_subdir:
        rank, _, world_size = _get_dist_info()
        is_distributed = world_size > 1

                                                                         
        session_key = _run_session_key(args)
        marker_path = os.path.join(output_dir_base, f".resolved_output_dir_{session_key}.txt")

        if is_distributed:
            if rank == 0:
                os.makedirs(output_dir_base, exist_ok=True)
                run_name = args.run_name if args.run_name else _build_run_name(args)
                run_name = _sanitize_for_path(run_name, 220)
                final_out = os.path.join(output_dir_base, run_name)

                                                                     
                if os.path.exists(final_out):
                    for i in range(1, 1000):
                        cand = f"{final_out}-{i}"
                        if not os.path.exists(cand):
                            final_out = cand
                            break

                os.makedirs(final_out, exist_ok=True)
                with open(marker_path, "w", encoding="utf-8") as f:
                    f.write(final_out)
            else:
                _wait_for_file(marker_path, timeout_s=600.0, poll_s=0.2)

                                                    
            with open(marker_path, "r", encoding="utf-8") as f:
                args.output_dir = f.read().strip()
        else:
            run_name = args.run_name if args.run_name else _build_run_name(args)
            run_name = _sanitize_for_path(run_name, 220)
            final_out = os.path.join(output_dir_base, run_name)
                             
            if os.path.exists(final_out):
                for i in range(1, 1000):
                    cand = f"{final_out}-{i}"
                    if not os.path.exists(cand):
                        final_out = cand
                        break
            args.output_dir = final_out
            os.makedirs(args.output_dir, exist_ok=True)

                         
    if os.path.exists(args.model_name):
        print(f"✅ 检测到本地模型路径: {args.model_name}")
    else:
        print(f"📥 将从HuggingFace下载模型: {args.model_name}")
    
    print("="*50)
    print("LoRA微调配置:")
    print(f"  模型: {args.model_name}")
    print(f"  训练数据: {args.train_data}")
    print(f"  验证数据: {args.val_data}")
    print(f"  输出目录: {args.output_dir}")
    print(f"  LoRA秩: {args.lora_r}")
    print(f"  训练轮数: {args.epochs}")
    print(f"  批次大小: {args.batch_size}")
    print(f"  学习率: {args.learning_rate}")
    print("="*50)
    
            
    lora_config = {
        'r': args.lora_r,
        'lora_alpha': args.lora_alpha,
        'target_modules': ['q_proj', 'v_proj', 'k_proj', 'o_proj', 'gate_proj', 'up_proj', 'down_proj'],
        'lora_dropout': args.lora_dropout,
        'bias': 'none',
        'task_type': TaskType.CAUSAL_LM
    }
    
          
    training_args_dict = {
        'num_train_epochs': args.epochs,
        'per_device_train_batch_size': args.batch_size,
        'per_device_eval_batch_size': args.batch_size,
        'gradient_accumulation_steps': args.gradient_accumulation,
        'learning_rate': args.learning_rate,
        'warmup_steps': args.warmup_steps,
        'logging_steps': 10,
        'save_steps': 500,
        'eval_steps': 500,
        'save_total_limit': 3,
        'fp16': args.fp16,
        'eval_strategy': 'steps' if args.val_data else 'no',                     
        'load_best_model_at_end': True if args.val_data else False,
                                                                                         
                                                                                                
        'report_to': (
            'none'
            if os.environ.get("WANDB_DISABLED")
            else ('wandb' if args.wandb_project else 'none')
        ),
                                                                          
        'disable_tqdm': True if (is_distributed and rank != 0) else False,
                             
        'gradient_checkpointing': True,
                                                               
                                                                               
                                                                               
        'gradient_checkpointing_kwargs': {'use_reentrant': False},
                                                                                             
                                                                                                 
                                                                                                
        'ddp_find_unused_parameters': (
            True
            if (torch.cuda.device_count() > 1 and (args.alpha_copy > 0 or args.beta_struct > 0))
            else (False if torch.cuda.device_count() > 1 else None)
        ),
    }
    
           
    trainer = LoRATrainer(
        model_name=args.model_name,
        lora_config=lora_config,
        training_args=training_args_dict,
        quantization=args.quantization,
        device=args.device
    )
    
          
    trainer.train(
        train_data_path=args.train_data,
        val_data_path=args.val_data,
        output_dir=args.output_dir,
        wandb_project=args.wandb_project,
        prompt_format=args.prompt_format,
        max_length=args.max_length,
        alpha_copy=args.alpha_copy,
        beta_struct=args.beta_struct,
        struct_temperature=args.struct_temperature,
    )
    
          
    print("\n" + "="*50)
    print("测试推理:")
    test_instruction = "Analyze the provided Solidity function code for security vulnerabilities."
    test_input = """### Target Function:
function transfer(address to, uint256 value) public returns (bool) {
    balances[msg.sender] -= value;
    balances[to] += value;
    return true;
}

### Contract Context:
- Contract: Token
"""
    
    response = trainer.inference(test_instruction, test_input)
    print(f"\nInstruction: {test_instruction}")
    print(f"Input: {test_input}")
    print(f"Response: {response}")
    print("="*50)


if __name__ == "__main__":
    main()

