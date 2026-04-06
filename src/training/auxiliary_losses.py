from __future__ import annotations
from typing import Optional
import torch
import torch.nn as nn
import torch.nn.functional as F

class CopyMechanismHead(nn.Module):

    def __init__(self, hidden_size: int):
        super().__init__()
        self.copy_proj = nn.Linear(hidden_size, hidden_size, bias=False)

    def forward(self, decoder_hidden: torch.Tensor, encoder_hidden: torch.Tensor, copy_labels: torch.Tensor) -> torch.Tensor:
        (batch_size, tgt_len, _) = decoder_hidden.shape
        src_len = encoder_hidden.shape[1]
        if tgt_len == 0 or src_len == 0:
            return torch.tensor(0.0, device=decoder_hidden.device, requires_grad=True)
        query = self.copy_proj(decoder_hidden)
        copy_scores = torch.bmm(query, encoder_hidden.transpose(1, 2))
        copy_probs = F.softmax(copy_scores, dim=-1)
        valid_mask = (copy_labels >= 0).float()
        if valid_mask.sum() == 0:
            return torch.tensor(0.0, device=decoder_hidden.device, requires_grad=True)
        safe_labels = copy_labels.clamp(min=0, max=src_len - 1)
        batch_idx = torch.arange(batch_size, device=copy_labels.device).unsqueeze(1)
        seq_idx = torch.arange(tgt_len, device=copy_labels.device).unsqueeze(0)
        selected_probs = copy_probs[batch_idx, seq_idx, safe_labels]
        copy_loss = -torch.log(selected_probs + 1e-10) * valid_mask
        return copy_loss.sum() / (valid_mask.sum() + 1e-10)

class ContrastiveStructuralLoss(nn.Module):

    def __init__(self, hidden_size: int, projection_dim: int=256, temperature: float=0.07):
        super().__init__()
        self.temperature = temperature
        self.projection = nn.Sequential(nn.Linear(hidden_size, hidden_size), nn.GELU(), nn.Linear(hidden_size, projection_dim))

    def forward(self, input_hidden: torch.Tensor, output_hidden: torch.Tensor, input_mask: torch.Tensor, output_mask: torch.Tensor) -> torch.Tensor:
        h_x = self._masked_mean_pool(input_hidden, input_mask)
        h_y = self._masked_mean_pool(output_hidden, output_mask)
        h_x = F.normalize(self.projection(h_x), p=2, dim=-1)
        h_y = F.normalize(self.projection(h_y), p=2, dim=-1)
        sim_matrix = torch.mm(h_x, h_y.t()) / self.temperature
        labels = torch.arange(h_x.size(0), device=h_x.device)
        loss_i2o = F.cross_entropy(sim_matrix, labels)
        loss_o2i = F.cross_entropy(sim_matrix.t(), labels)
        return (loss_i2o + loss_o2i) / 2

    def _masked_mean_pool(self, hidden: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        mask = mask.to(dtype=hidden.dtype)
        mask_expanded = mask.unsqueeze(-1).expand_as(hidden)
        sum_hidden = (hidden * mask_expanded).sum(dim=1)
        denom = mask_expanded.sum(dim=1).clamp(min=1e-09)
        return sum_hidden / denom

def compute_copy_labels(input_ids: torch.Tensor, output_ids: torch.Tensor, output_mask: Optional[torch.Tensor]=None, ignore_token_id: Optional[int]=None, min_token_id: int=3) -> torch.Tensor:
    if input_ids.dim() == 1:
        input_ids = input_ids.unsqueeze(0)
    if output_ids.dim() == 1:
        output_ids = output_ids.unsqueeze(0)
    batch_size = input_ids.size(0)
    tgt_len = output_ids.size(1)
    copy_labels = torch.full((batch_size, tgt_len), -1, dtype=torch.long, device=input_ids.device)
    if output_mask is None:
        output_mask = torch.ones_like(output_ids, dtype=torch.bool, device=output_ids.device)
    else:
        output_mask = output_mask.to(dtype=torch.bool, device=output_ids.device)
    for b in range(batch_size):
        input_pos = {}
        for (i, tok) in enumerate(input_ids[b].tolist()):
            if tok < min_token_id:
                continue
            if ignore_token_id is not None and tok == ignore_token_id:
                continue
            if tok not in input_pos:
                input_pos[tok] = i
        for (j, tok) in enumerate(output_ids[b].tolist()):
            if not bool(output_mask[b, j]):
                continue
            if tok < min_token_id:
                continue
            if ignore_token_id is not None and tok == ignore_token_id:
                continue
            if tok in input_pos:
                copy_labels[b, j] = input_pos[tok]
    return copy_labels
