import math
import re
import difflib
from typing import List, Dict, Any
try:
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False

def remove_comments(code: str) -> str:
    code = re.sub('/\\*.*?\\*/', '', code, flags=re.DOTALL)
    code = re.sub('//.*?$', '', code, flags=re.MULTILINE)
    return code

def calculate_pass_at_k(n: int, c: int, k: int) -> float:
    if n < k:
        return 0.0
    if c == n:
        return 1.0
    prob_fail = 1.0
    for i in range(k):
        prob_fail *= (n - c - i) / (n - i)
    return 1.0 - prob_fail

def calculate_vrr(total_samples: int, fixed_samples: int) -> float:
    if total_samples == 0:
        return 0.0
    return fixed_samples / total_samples

def calculate_bleu(reference_code: str, candidate_code: str) -> float:
    if not NLTK_AVAILABLE:
        return 0.0
    ref_no_comments = remove_comments(reference_code)
    cand_no_comments = remove_comments(candidate_code)
    ref_tokens = ref_no_comments.split()
    cand_tokens = cand_no_comments.split()
    cc = SmoothingFunction()
    return sentence_bleu([ref_tokens], cand_tokens, smoothing_function=cc.method1)

def _tokenize_for_similarity(code: str) -> List[str]:
    if not code:
        return []
    s = remove_comments(str(code))
    return s.split()

def calculate_edit_similarity(reference_code: str, candidate_code: str) -> float:
    ref_toks = _tokenize_for_similarity(reference_code)
    cand_toks = _tokenize_for_similarity(candidate_code)
    if not ref_toks or not cand_toks:
        return 0.0
    return difflib.SequenceMatcher(a=ref_toks, b=cand_toks).ratio()

def compute_metrics(results: List[Dict[str, Any]], k_values: List[int]=[1, 5, 10]) -> Dict[str, float]:
    metrics = {}
    solved_problems = sum((1 for r in results if r['correct_generated'] > 0))
    metrics['solved_rate'] = solved_problems / len(results) if results else 0
    for k in k_values:
        pass_at_k_scores = []
        for res in results:
            n = res['total_generated']
            c = res['correct_generated']
            if n >= k:
                score = calculate_pass_at_k(n, c, k)
                pass_at_k_scores.append(score)
        if pass_at_k_scores:
            metrics[f'pass@{k}'] = sum(pass_at_k_scores) / len(pass_at_k_scores)
        else:
            metrics[f'pass@{k}'] = 0.0
    bleu_scores_all = []
    bleu_scores_solved = []
    bleu_scores_unsolved = []
    for res in results:
        if 'reference_code' in res and res['reference_code'] and ('best_candidate_code' in res) and res['best_candidate_code']:
            bleu = calculate_bleu(res['reference_code'], res['best_candidate_code'])
            bleu_scores_all.append(bleu)
            if res.get('correct_generated', 0) > 0:
                bleu_scores_solved.append(bleu)
            else:
                bleu_scores_unsolved.append(bleu)
    if bleu_scores_all:
        metrics['bleu'] = sum(bleu_scores_all) / len(bleu_scores_all)
        metrics['bleu_all'] = metrics['bleu']
    if bleu_scores_solved:
        metrics['bleu_solved'] = sum(bleu_scores_solved) / len(bleu_scores_solved)
    if bleu_scores_unsolved:
        metrics['bleu_unsolved'] = sum(bleu_scores_unsolved) / len(bleu_scores_unsolved)
    edit_scores_all = []
    edit_scores_solved = []
    edit_scores_unsolved = []
    highest_edit_scores = []
    for res in results:
        ref = res.get('reference_code')
        best = res.get('best_candidate_code')
        if ref and best:
            sim = calculate_edit_similarity(ref, best)
            edit_scores_all.append(sim)
            if res.get('correct_generated', 0) > 0:
                edit_scores_solved.append(sim)
            else:
                edit_scores_unsolved.append(sim)
        passed = res.get('passed_candidate_codes')
        if ref and isinstance(passed, list) and passed:
            sims = []
            for cand in passed:
                if not cand:
                    continue
                sims.append(calculate_edit_similarity(ref, cand))
            if sims:
                highest_edit_scores.append(max(sims))
    if edit_scores_all:
        metrics['edit_sim'] = sum(edit_scores_all) / len(edit_scores_all)
        metrics['edit_sim_all'] = metrics['edit_sim']
    if edit_scores_solved:
        metrics['edit_sim_solved'] = sum(edit_scores_solved) / len(edit_scores_solved)
    if edit_scores_unsolved:
        metrics['edit_sim_unsolved'] = sum(edit_scores_unsolved) / len(edit_scores_unsolved)
    if highest_edit_scores:
        metrics['highest_edit_sim'] = sum(highest_edit_scores) / len(highest_edit_scores)
    return metrics
