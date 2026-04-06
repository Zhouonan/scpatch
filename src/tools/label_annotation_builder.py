from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

@dataclass
class LabelAnnotationBuildResult:
    annotation: Dict[str, Any]
    vulnerable_code_details: str = ''
    slither_section: str = ''

class LabelAnnotationBuilder:

    def build(self, func_data: Dict[str, Any]) -> Optional[LabelAnnotationBuildResult]:
        label = func_data.get('label') or {}
        slither_result = func_data.get('slither_result') or {}
        is_vulnerable = bool(label.get('is_vulnerable'))
        if not is_vulnerable:
            return None
        (vuln_types, vuln_details) = self._extract_vuln_types_and_details(label)
        severity = self._extract_severity(label, slither_result)
        vulnerable_code_details = self._build_vulnerable_code_details(func_code=str(func_data.get('function_code') or ''), func_start_line=int(func_data.get('start_line') or 1), vuln_details=vuln_details)
        slither_section = self._build_slither_section(slither_result)
        analysis = self._build_analysis(vuln_types=vuln_types, label=label, slither_result=slither_result)
        annotation: Dict[str, Any] = {'label': 'vulnerable', 'vulnerability_types': vuln_types, 'severity': severity, 'analysis': analysis, 'ground_truth_label': label, 'slither_result': slither_result, 'vulnerable_code_details': vulnerable_code_details, 'slither_section': slither_section}
        return LabelAnnotationBuildResult(annotation=annotation, vulnerable_code_details=vulnerable_code_details, slither_section=slither_section)

    def _extract_vuln_types_and_details(self, label: Dict[str, Any]) -> Tuple[List[str], List[Dict[str, Any]]]:
        vuln_types: List[str] = []
        vuln_details: List[Dict[str, Any]] = []
        vt = label.get('vulnerability_types')
        if isinstance(vt, list):
            vuln_types.extend([str(x) for x in vt if str(x).strip()])
        elif isinstance(vt, str) and vt.strip():
            vuln_types.append(vt.strip())
        details = label.get('vulnerability_details')
        if isinstance(details, list):
            vuln_details = [d for d in details if isinstance(d, dict)]
            if not vuln_types:
                for d in vuln_details:
                    t = d.get('type') or d.get('category')
                    if isinstance(t, str) and t.strip():
                        vuln_types.append(t.strip())
        seen = set()
        deduped: List[str] = []
        for t in vuln_types:
            key = t.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(t)
        return (deduped, vuln_details)

    def _extract_severity(self, label: Dict[str, Any], slither_result: Dict[str, Any]) -> float:
        sev = label.get('severity')
        try:
            if sev is not None:
                return float(sev)
        except Exception:
            pass
        details = slither_result.get('vulnerability_details')
        if isinstance(details, list) and details:
            severity_order = {'High': 9.0, 'Medium': 6.0, 'Low': 3.0, 'Informational': 1.0, 'Optimization': 1.0}
            best = 0.0
            for d in details:
                if not isinstance(d, dict):
                    continue
                s = d.get('severity')
                if isinstance(s, str):
                    best = max(best, severity_order.get(s, 0.0))
            if best > 0:
                return best
        return 0.0

    def _build_analysis(self, vuln_types: List[str], label: Dict[str, Any], slither_result: Dict[str, Any]) -> str:
        for k in ('description', 'reasoning', 'analysis'):
            v = label.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        types_s = ', '.join(vuln_types) if vuln_types else 'unknown'
        slither_flag = slither_result.get('is_vulnerable')
        slither_s = 'Slither also flagged issues.' if slither_flag else 'Slither did not flag issues (may be false-negative).'
        return f'Ground-truth label indicates this function is vulnerable. Vulnerability types: {types_s}. {slither_s}'

    def _build_vulnerable_code_details(self, func_code: str, func_start_line: int, vuln_details: List[Dict[str, Any]]) -> str:
        if not vuln_details:
            return ''
        if not func_code.strip():
            lines_out: List[str] = ['## Vulnerable Code Details (Ground Truth)']
            for (i, v) in enumerate(vuln_details, 1):
                category = v.get('category') or v.get('type') or 'unknown'
                lines = v.get('lines') or []
                lines_out.append(f'- Vulnerability {i}: category={category}, lines={lines}')
            return '\n'.join(lines_out)
        out: List[str] = ['## Vulnerable Code Details (Ground Truth)']
        for (i, v) in enumerate(vuln_details, 1):
            category = v.get('category') or v.get('type') or 'unknown'
            lines = v.get('lines') or []
            if isinstance(lines, list) and lines:
                snippet = self._extract_vulnerable_code(func_code, lines, func_start_line)
                out.append(f'\n**Vulnerability {i}** (Category: {category})\nLines: {lines}\n')
                out.append('```solidity')
                out.append(snippet)
                out.append('```')
            else:
                out.append(f'\n**Vulnerability {i}** (Category: {category})\nLines: {lines}\n')
        return '\n'.join(out).strip()

    def _extract_vulnerable_code(self, func_code: str, line_numbers: List[Any], func_start_line: int) -> str:
        try:
            func_start_line = int(func_start_line or 1)
        except Exception:
            func_start_line = 1
        rel: List[int] = []
        for ln in line_numbers:
            try:
                ln_i = int(ln)
            except Exception:
                continue
            rel_i = ln_i - func_start_line
            rel.append(rel_i)
        lines = func_code.split('\n')
        rel = [i for i in rel if 0 <= i < len(lines)]
        if not rel:
            return ''
        (min_i, max_i) = (min(rel), max(rel))
        context = 1
        start = max(0, min_i - context)
        end = min(len(lines) - 1, max_i + context)
        out_lines: List[str] = []
        for i in range(start, end + 1):
            original_ln = func_start_line + i
            prefix = f'// Line {original_ln}'
            if i in set(rel):
                prefix += ' (VULNERABLE): '
            else:
                prefix += ': '
            out_lines.append(prefix + lines[i])
        return '\n'.join(out_lines)

    def _build_slither_section(self, slither_result: Dict[str, Any]) -> str:
        if not slither_result:
            return ''
        has_findings = bool(slither_result.get('is_vulnerable', False))
        details = slither_result.get('vulnerability_details', [])
        out: List[str] = ['## Slither Analysis (Reference)']
        if has_findings and isinstance(details, list) and details:
            out.append('Slither found these issues:')
            out.append(self._build_slither_summary(details))
            out.append('')
            out.append('Note: Slither can have false positives. Verify each issue independently.')
        else:
            out.append('Slither found no critical vulnerabilities. But check carefully - it can miss issues.')
        return '\n'.join(out).strip()

    def _build_slither_summary(self, vulnerability_details: List[Dict[str, Any]]) -> str:
        if not vulnerability_details:
            return 'No vulnerabilities detected by Slither.'
        summary_lines: List[str] = []
        for (i, vuln) in enumerate(vulnerability_details, 1):
            if not isinstance(vuln, dict):
                continue
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Unknown')
            description = vuln.get('description', 'No description')
            summary_lines.append(f'{i}. **{vuln_type}** (Severity: {severity})')
            summary_lines.append(f'   {description}')
        return '\n'.join(summary_lines)
