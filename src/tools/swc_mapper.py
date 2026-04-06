\
\
\
\
\
   

from __future__ import annotations

import re
from typing import Iterable, Optional, Set, List


def _norm_key(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    s = s.replace("_", " ").replace("-", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _as_swc_id(x: str) -> Optional[str]:
    if not x:
        return None
    x = x.strip()
    if re.fullmatch(r"SWC-\d{3}", x):
        return x
                          
    if re.fullmatch(r"\d{1,3}", x):
        return f"SWC-{int(x):03d}"
    return None


def map_one_type_to_swcs(vuln_type: str) -> Set[str]:
\
\
\
       
    out: Set[str] = set()
    if not vuln_type:
        return out

                       
    swc = _as_swc_id(vuln_type)
    if swc:
        out.add(swc)
        return out

    key = _norm_key(vuln_type)

                                          
                                                                                                         
    canonical_map = {
        "reentrancy": "SWC-107",
        "reentrancy eth": "SWC-107",
        "tx origin": "SWC-115",
        "tx.origin": "SWC-115",
        "tx_origin": "SWC-115",
        "unchecked call": "SWC-104",
        "unchecked call return value": "SWC-104",
        "unchecked return": "SWC-104",
        "unchecked return value": "SWC-104",
        "unchecked low level calls": "SWC-104",
        "unchecked low-level calls": "SWC-104",
        "bad randomness": "SWC-120",
        "weak randomness": "SWC-120",
        "front running": "SWC-114",
        "front-running": "SWC-114",
        "transaction ordering dependence": "SWC-114",
        "tod": "SWC-114",
        "timestamp dependence": "SWC-116",
        "timestamp manipulation": "SWC-116",
        "time manipulation": "SWC-116",
        "miner manipulation": "SWC-116",
        "delegatecall": "SWC-112",
        "uninitialized storage": "SWC-109",
        "uninitialized storage pointer": "SWC-109",
        "storage corruption": "SWC-124",
        "storage collision": "SWC-124",
        "arbitrary storage write": "SWC-124",
        "assert violation": "SWC-110",
        "signature malleability": "SWC-117",
        "signature replay": "SWC-121",
        "replay attack": "SWC-121",
        "signature verification flaw": "SWC-122",
        "improper signature verification": "SWC-122",
        "forced ether reception": "SWC-132",
        "unexpected ether balance": "SWC-132",
        "hash collision risk": "SWC-133",
        "hash collisions": "SWC-133",
                      
        "selfdestruct": "SWC-106",
        "unchecked selfdestruct": "SWC-106",
        "contract destruction": "SWC-106",
                    
        "arithmetic": "SWC-101",
        "arithmetic error": "SWC-101",
        "integer overflow": "SWC-101",
        "integer underflow": "SWC-101",
        "integer overflow underflow": "SWC-101",
        "integer overflow/underflow": "SWC-101",
    }
    if key in canonical_map:
        out.add(canonical_map[key])
        return out

                       
    if "reentr" in key:
        out.add("SWC-107")
    if "tx origin" in key or "tx.origin" in key:
        out.add("SWC-115")
    if ("unchecked" in key and ("call" in key or "return" in key)) or "low level call" in key:
        out.add("SWC-104")
    if "selfdestruct" in key:
        out.add("SWC-106")
    if (
        "overflow" in key
        or "underflow" in key
        or "division" in key
        or "rounding" in key
        or "truncation" in key
        or "precision" in key
        or "arithmetic" in key
        or "math" in key
    ):
        out.add("SWC-101")
    if "random" in key or "prng" in key or "predictable" in key:
        out.add("SWC-120")
    if "front run" in key or "transaction ordering" in key or key == "tod":
        out.add("SWC-114")
    if "timestamp" in key or "time manipulation" in key or "miner manipulation" in key or "block variable" in key:
        out.add("SWC-116")
    if "delegatecall" in key:
        out.add("SWC-112")
    if "uninitialized" in key and "storage" in key:
        out.add("SWC-109")
    if "assert" in key:
        out.add("SWC-110")
    if "deprecated" in key or "throw" in key:
        out.add("SWC-111")
    if "dos" in key or "denial of service" in key or "failed send" in key or "failed call" in key:
        out.add("SWC-113")
    if "gas grief" in key:
        out.add("SWC-126")
    if "block gas" in key or "gas limit" in key or "unbounded loop" in key or "infinite loop" in key or "gas exhaustion" in key:
        out.add("SWC-128")
    if "signature malleability" in key:
        out.add("SWC-117")
    if "replay" in key and "signature" in key:
        out.add("SWC-121")
    if "signature verification" in key:
        out.add("SWC-122")
    if (
        "storage corruption" in key
        or "storage collision" in key
        or "state variable overwrite" in key
        or "state variable corruption" in key
        or "arbitrary write" in key
        or "arbitrary storage" in key
        or "out of bounds write" in key
    ):
        out.add("SWC-124")
    if "forced ether" in key or "unexpected ether" in key:
        out.add("SWC-132")
    if "hash collision" in key:
        out.add("SWC-133")

    return out


def map_types_to_swc_ids(
    vuln_types: Iterable[str],
    exclude_swcs: Optional[Iterable[str]] = None,
) -> List[str]:
\
\
       
    ex: Set[str] = set()
    if exclude_swcs:
        for e in exclude_swcs:
            sid = _as_swc_id(str(e))
            if sid:
                ex.add(sid)
            else:
                                                                     
                if str(e).startswith("SWC-") and re.fullmatch(r"SWC-\d{3}", str(e)):
                    ex.add(str(e))

    swcs: Set[str] = set()
    for t in vuln_types or []:
        swcs |= map_one_type_to_swcs(str(t))

    swcs = {s for s in swcs if s not in ex}
    return sorted(swcs)









