\
\
\
\
   

from __future__ import annotations

from typing import Iterable, List, Optional


def collect_slither_issues(
    slither: object,
    *,
    severities: Optional[Iterable[str]] = ("high", "medium", "low"),
) -> List[str]:
\
\
\
\
\
\
\
       
    if slither is None:
        return []

    sev_set = None
    if severities is not None:
        sev_set = {str(s).strip().lower() for s in severities if str(s).strip()}

    issues: List[str] = []
    detectors = getattr(slither, "detectors", None) or []
    for detector in detectors:
        results = getattr(detector, "results", None)
        if not results:
            continue
        for res in results:
            sev = getattr(res, "severity", None)
            if sev is None:
                sev = getattr(res, "impact", None)
            sev_s = str(sev).strip().lower() if sev is not None else ""
            if not sev_s:
                continue
            if sev_set is not None and sev_s not in sev_set:
                continue

            desc = getattr(res, "description", "") or ""
            check_name = getattr(res, "check", None)
            if not check_name:
                check_name = getattr(detector, "ARGUMENT", "UnknownCheck")
            issues.append(f"{check_name}: {desc}")

    return issues


