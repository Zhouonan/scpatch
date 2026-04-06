from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

def _truncate_lines(s: str, max_lines: int=30, max_chars: int=4000) -> str:
    s = (s or '').strip()
    if not s:
        return ''
    lines = s.splitlines()
    out = '\n'.join(lines[:max_lines])
    if len(out) > max_chars:
        out = out[:max_chars] + '\n...<truncated>...'
    if len(lines) > max_lines:
        out = out + f'\n...<truncated {len(lines) - max_lines} lines>...'
    return out

@dataclass
class MythrilResult:
    passed: bool
    issue_count: int
    issues: List[str]
    error: Optional[str] = None
    raw_json: Optional[Dict[str, Any]] = None

class MythrilManager:

    def __init__(self, debug: bool=False, mythril_bin: str='myth'):
        self.debug = debug
        self.mythril_bin = mythril_bin

    def is_available(self) -> bool:
        return bool(shutil.which(self.mythril_bin))

    def _build_cmd(self, contract_file: str) -> List[str]:
        return [self.mythril_bin, 'analyze', contract_file, '-o', 'json']

    def _parse_json_output(self, stdout: str, severities: Optional[Iterable[str]]=None, max_issues: int=50) -> Tuple[bool, int, List[str], Optional[Dict[str, Any]]]:
        severities_norm = None
        if severities is not None:
            severities_norm = {str(s).strip().lower() for s in severities if str(s).strip()}
        raw = json.loads(stdout or '{}')
        issues_obj = raw.get('issues')
        if not isinstance(issues_obj, list):
            issues_obj = raw.get('results') if isinstance(raw.get('results'), list) else []
        issues: List[str] = []
        for it in issues_obj:
            if not isinstance(it, dict):
                continue
            sev = str(it.get('severity') or it.get('impact') or '').strip()
            sev_l = sev.lower()
            if severities_norm is not None and sev_l and (sev_l not in severities_norm):
                continue
            title = str(it.get('title') or it.get('description_head') or it.get('name') or 'Issue').strip()
            swc = str(it.get('swc-id') or it.get('swcID') or it.get('swc_id') or '').strip()
            desc = str(it.get('description') or '').strip()
            desc = _truncate_lines(desc, max_lines=6, max_chars=800)
            loc = it.get('locations') or it.get('locations_in_code') or []
            loc_s = ''
            try:
                if isinstance(loc, list) and loc:
                    l0 = loc[0]
                    if isinstance(l0, dict):
                        line = l0.get('lineno') or l0.get('line')
                        col = l0.get('col_offset') or l0.get('column')
                        if line is not None:
                            loc_s = f' @L{line}' + (f':{col}' if col is not None else '')
            except Exception:
                loc_s = ''
            head = f"{(swc + ' ' if swc else '')}{title}".strip()
            if sev:
                head = f'{head} ({sev})'
            if loc_s:
                head = f'{head}{loc_s}'
            if desc:
                issues.append(f'{head}: {desc}')
            else:
                issues.append(head)
            if len(issues) >= max_issues:
                break
        passed = len(issues) == 0
        return (passed, len(issues), issues, raw)

    def _parse_text_fallback(self, text: str, max_issues: int=50) -> Tuple[bool, int, List[str]]:
        t = (text or '').strip()
        if not t:
            return (True, 0, [])
        if 'no issues found' in t.lower():
            return (True, 0, [])
        issues: List[str] = []
        for ln in t.splitlines():
            if 'swc' in ln.lower() or 'issue' in ln.lower():
                issues.append(ln.strip())
                if len(issues) >= max_issues:
                    break
        if not issues:
            issues = [_truncate_lines(t, max_lines=12, max_chars=1200)]
        return (False, len(issues), issues)

    def analyze_contract(self, contract_file: str, timeout: int=120, severities: Optional[Iterable[str]]=('high', 'medium'), max_issues: int=50) -> MythrilResult:
        if not self.is_available():
            return MythrilResult(passed=True, issue_count=0, issues=[], error=f'mythril_not_found: {self.mythril_bin}', raw_json=None)
        if not os.path.exists(contract_file):
            return MythrilResult(passed=True, issue_count=0, issues=[], error=f'contract_not_found: {contract_file}', raw_json=None)
        cmd = self._build_cmd(contract_file)
        if self.debug:
            sev_s = None
            try:
                sev_s = ', '.join(list(severities)) if severities is not None else 'ALL'
            except Exception:
                sev_s = 'ALL'
            print(f'[mythril] starting analyze (timeout={timeout}s, severities={sev_s}, max_issues={max_issues})')
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, int(timeout)))
        except subprocess.TimeoutExpired:
            return MythrilResult(passed=True, issue_count=0, issues=[], error=f'mythril_timeout: {timeout}s', raw_json=None)
        except Exception as e:
            return MythrilResult(passed=True, issue_count=0, issues=[], error=f'mythril_error: {type(e).__name__}: {e}', raw_json=None)
        stdout = (out.stdout or '').strip()
        stderr = (out.stderr or '').strip()
        if self.debug:
            print(f"[mythril] rc={out.returncode} cmd={' '.join(cmd)}")
            if stderr:
                print('[mythril] stderr:\n' + _truncate_lines(stderr))
            if stdout:
                print('[mythril] stdout:\n' + _truncate_lines(stdout))
        raw_json: Optional[Dict[str, Any]] = None
        try:
            (passed, n, issues, raw_json) = self._parse_json_output(stdout, severities=severities, max_issues=max_issues)
            return MythrilResult(passed=passed, issue_count=n, issues=issues, error=None, raw_json=raw_json)
        except Exception:
            pass
        try:
            (passed, n, issues, raw_json) = self._parse_json_output(stderr, severities=severities, max_issues=max_issues)
            return MythrilResult(passed=passed, issue_count=n, issues=issues, error=None, raw_json=raw_json)
        except Exception:
            pass
        combined = (stdout + '\n' + stderr).strip()
        (passed, n, issues) = self._parse_text_fallback(combined, max_issues=max_issues)
        err = None if out.returncode == 0 else f'mythril_rc={out.returncode}'
        return MythrilResult(passed=passed, issue_count=n, issues=issues, error=err, raw_json=None)

    def analyze_source(self, contract_src: str, timeout: int=120, severities: Optional[Iterable[str]]=('high', 'medium'), max_issues: int=50, suffix: str='.sol') -> MythrilResult:
        (fd, tmp) = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        try:
            if self.debug:
                sev_s = None
                try:
                    sev_s = ', '.join(list(severities)) if severities is not None else 'ALL'
                except Exception:
                    sev_s = 'ALL'
                print(f'[mythril] temp file: {tmp}')
                print(f'[mythril] config: timeout={timeout}s severities={sev_s} max_issues={max_issues}')
            Path(tmp).write_text(contract_src or '', encoding='utf-8', errors='ignore')
            return self.analyze_contract(tmp, timeout=timeout, severities=severities, max_issues=max_issues)
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass

    @contextmanager
    def analyze_contract_ctx(self, contract_file: str, timeout: int=120, severities: Optional[Iterable[str]]=('high', 'medium'), max_issues: int=50):
        res = self.analyze_contract(contract_file, timeout=timeout, severities=severities, max_issues=max_issues)
        try:
            yield res
        finally:
            pass

def analyze_with_mythril(contract_file: str, debug: bool=False, timeout: int=120, severities: Optional[Iterable[str]]=('high', 'medium'), max_issues: int=50) -> MythrilResult:
    mgr = MythrilManager(debug=debug)
    return mgr.analyze_contract(contract_file, timeout=timeout, severities=severities, max_issues=max_issues)
