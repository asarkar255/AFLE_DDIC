# app_amount_scan_webaware_decl_multiline.py (v1.6)
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os, re
import time
from datetime import datetime
# HTTP client placeholder (kept to preserve _scanner_mode/health structure)
_http = None

app = FastAPI(
    title="Amount Field Scanner (AFLE) — reduced false positives, decl mirrors, multiline decls",
    version="1.6"
)

# =========================
# Tunables (env-controlled)
# =========================
MIN_CHAR_FOR_AMOUNT    = int(os.getenv("MIN_CHAR_FOR_AMOUNT", "25"))   # suggested char width for formatted amounts
MIN_DIGITS_FOR_AMOUNT  = int(os.getenv("MIN_DIGITS_FOR_AMOUNT", "23")) # P/DEC total length to be AFLE-safe
DEFAULT_DECIMALS       = int(os.getenv("DEFAULT_DECIMALS", "2"))       # assume 2 decimals if unknown
SUPPRESS_UNKNOWN       = os.getenv("SUPPRESS_UNKNOWN", "false").lower() == "true"

# =========================
# Models
# =========================
class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: str
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: str

# =========================
# Regexes (AFLE scanning)
# =========================
DECL_CHAR_LEN_PAREN = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*\((\d+)\)\s*TYPE\s*C\b", re.IGNORECASE)
DECL_CHAR_LEN_EXPL  = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s*C\b[^.\n]*?\bLENGTH\b\s*(\d+)", re.IGNORECASE)
DECL_PACKED         = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+P\b[^.\n]*?(LENGTH\s+(\d+))?[^.\n]*?(DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_DEC_TYPE       = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+DEC\b[^.\n]*?(LENGTH\s+(\d+))?[^.\n]*?(DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_TYPE_GENERIC   = re.compile(r"\b(DATA|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+(\w+)\b", re.IGNORECASE)

ASSIGNMENT          = re.compile(r"\b(\w+)\s*=\s*([^\.\n]+)\.", re.IGNORECASE)
MOVE_STMT           = re.compile(r"\bMOVE\b\s+(.+?)\s+\bTO\b\s+(\w+)\s*\.", re.IGNORECASE)

# SELECT: capture select list (group 1) and INTO dest (group 2)
SELECT_INTO         = re.compile(r"\bSELECT\b\s*(.+?)\bINTO\b\s+@?(\w+)\b", re.IGNORECASE | re.DOTALL)

IF_BLOCK            = re.compile(r"\bIF\b\s+(.+?)\.\s*", re.IGNORECASE | re.DOTALL)
SIMPLE_CMP          = re.compile(r"(\w+)\s*(=|<>|NE|EQ|LT|LE|GT|GE)\s*('?[\w\.\-]+'?|\w+)", re.IGNORECASE)

CONCATENATE_STMT    = re.compile(r"\bCONCATENATE\b(.+?)\bINTO\b", re.IGNORECASE | re.DOTALL)
STRING_OP_AND       = re.compile(r"(.+?)\s*&&\s*(.+?)")
STRING_TEMPLATE     = re.compile(r"\|.*?\{[^}]*\}\|", re.IGNORECASE | re.DOTALL)
OFFSET_LEN          = re.compile(r"\b(\w+(?:-\w+)?)\s*\+\s*(\d+)\s*\(\s*(\d+)\s*\)", re.IGNORECASE)
WRITE_STMT          = re.compile(r"^\s*WRITE(\s*[:]?)(.+)", re.IGNORECASE | re.MULTILINE)
WRITE_TO_STMT       = re.compile(r"\bWRITE\s+(.+?)\bTO\b\s+(\w+)\b", re.IGNORECASE)
FLOAT_TYPES_DECL    = re.compile(r"\bTYPE\s+(F|DECFLOAT16)\b", re.IGNORECASE)
EXPONENT_OP         = re.compile(r"\*\*")
MOVE_CORRESP        = re.compile(r"\bMOVE-CORRESPONDING\b", re.IGNORECASE)
IMPORT_DB           = re.compile(r"\bIMPORT\b.+\bFROM\b\s+DATABASE\b(?![^.]*ACCEPTING\s+PADDING)", re.IGNORECASE | re.DOTALL)
REUSE_ALV_LOAD      = re.compile(r"\bREUSE_ALV_EXTRACT_LOAD\b", re.IGNORECASE)
I_ACCEPT_PADDING    = re.compile(r"I_ACCEPT_PADDING\s*=\s*'X'", re.IGNORECASE)
CDS_CAST_DEC        = re.compile(r"\bcast\s*\([^)]+as\s+abap\.(?:dec|curr)\s*\(\s*\d+\s*,\s*\d+\s*\)\s*\)", re.IGNORECASE)
CDS_UNION           = re.compile(r"\bselect\b.+\bunion\b", re.IGNORECASE | re.DOTALL)

# Heuristic amount field names
AMOUNT_NAME_HINT    = re.compile(r"\b(dmbtr|wrbtr|bapicurr|betrag|amount|amt|kbetr|netwr|mwskz)\b", re.IGNORECASE)

# For declaration indexing (line-by-line single-entry)
DECL_LINE_PATTERNS = [
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s*:\s*(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s+(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*FIELD-SYMBOLS\s*<(\w+)>\b.*\.\s*$", re.IGNORECASE),
]

# --- Multi-line colon-style declarations ---
def iter_statements_with_offsets(src: str):
    """Yield (statement_text, start_offset, end_offset) for each '.'-terminated statement."""
    buf = []
    start_off = 0
    for i, ch in enumerate(src):
        buf.append(ch)
        if ch == ".":
            stmt = "".join(buf)
            yield stmt, start_off, i + 1
            buf = []
            start_off = i + 1
    if buf:
        yield "".join(buf), start_off, len(src)

def smart_split_commas(s: str):
    """Split a multi-declaration body by commas, respecting quotes."""
    parts, cur, q, i = [], [], False, 0
    while i < len(s):
        c = s[i]
        if c == "'":
            q = not q
            cur.append(c)
        elif c == "," and not q:
            parts.append("".join(cur).strip()); cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]

DECL_HEADER_COLON = re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s*:\s*(.+)$", re.IGNORECASE | re.DOTALL)

DECL_ENTRY = re.compile(
    r"^\s*(?P<var>\w+)\s*(?:"                         # name
    r"TYPE\s+(?P<dtype>\w+)"                          # TYPE DTYPE
    r"(?:\s+LENGTH\s+(?P<len>\d+))?"                  # optional LENGTH
    r"(?:\s+DECIMALS\s+(?P<dec>\d+))?"                # optional DECIMALS
    r"|LIKE\s+(?P<like>\w+)"                          # OR LIKE ref
    r"|\((?P<charlen>\d+)\)\s*TYPE\s*C"               # OR (n) TYPE C
    r")?", re.IGNORECASE
)

# =========================
# Utilities
# =========================
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet(text: str, start: int, end: int) -> str:
    s = max(0, start - 60); e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def pack_issue(unit, issue_type, message, severity, start, end, meta=None):
    src = unit.code or ""
    return {
        "pgm_name": unit.pgm_name,
        "inc_name": unit.inc_name,
        "type": unit.type,
        "name": unit.name,
        "class_implementation": unit.class_implementation,
        "start_line": unit.start_line,
        "end_line": unit.end_line,
        "issue_type": issue_type,
        "severity": severity,
        "line": line_of_offset(src, start),
        "message": message,
        "suggestion": (meta or {}).pop("suggestion", ""),
        "snippet": snippet(src, start, end),
        "meta": meta or {}
    }

def pack_decl_issue(decl_unit: Unit, decl_line: int, decl_text: str,
                    issue_type: str, message: str, severity: str, meta=None):
    return {
        "pgm_name": decl_unit.pgm_name,
        "inc_name": decl_unit.inc_name,
        "type": decl_unit.type,
        "name": decl_unit.name,
        "class_implementation": decl_unit.class_implementation,
        "start_line": decl_unit.start_line,
        "end_line": decl_unit.end_line,
        "issue_type": issue_type,
        "severity": severity,
        "line": decl_line,
        "message": message,
        "suggestion": (meta or {}).pop("suggestion", ""),
        "snippet": decl_text,
        "meta": meta or {}
    }

# =========================
# Resolvers: stubs (SAP/Tavily removed)
# =========================
class _NullResolver:
    enabled = False
    def data_element(self, *args, **kwargs) -> Optional[Dict[str, Any]]:
        return None
    def table_field(self, *args, **kwargs) -> Optional[Dict[str, Any]]:
        return None

sap = _NullResolver()
tav = _NullResolver()

# =========================
# Symbol table & lookups
# =========================
def ddic_lookup_token(token: str) -> Optional[Dict[str, Any]]:
    """Try to classify token via DDIC stubs; fallback to name-hint."""
    if not token:
        return None
    t = token.strip().upper()

    # Table-field like BSEG-DMBTR?
    if "-" in t:
        parts = t.split("-")
        if len(parts) == 2:
            tab, fld = parts[0], parts[1]
            tf = sap.table_field(tab, fld) or tav.table_field(tab, fld)
            if tf:
                kind = "amount" if tf.get("dec") is not None else "char"
                return {"len": tf.get("len"), "dec": tf.get("dec"), "kind": kind, "source": tf.get("source")}
            if AMOUNT_NAME_HINT.search(fld):
                return {"len": None, "dec": None, "kind": "amount", "source": "regex_name_hint"}
        return None

    # Data element like DMBTR?
    de = sap.data_element(t) or tav.data_element(t)
    if de:
        kind = "amount" if de.get("dec") is not None else "char"
        return {"len": de.get("len"), "dec": de.get("dec"), "kind": kind, "source": de.get("source")}
    if AMOUNT_NAME_HINT.search(t):
        return {"len": None, "dec": None, "kind": "amount", "source": "regex_name_hint"}
    return None

DECL_SPLIT = re.compile(r"\.", re.DOTALL)

def build_symbol_table(full_src: str) -> Dict[str, Dict[str, Any]]:
    st: Dict[str, Dict[str, Any]] = {}
    for stmt, _, _ in iter_statements_with_offsets(full_src):
        s = stmt.strip()
        if not s:
            continue
        # single-line patterns
        m = DECL_CHAR_LEN_PAREN.search(s)
        if m: st[m.group(2).lower()] = {"kind":"char","len":int(m.group(3))}
        m = DECL_CHAR_LEN_EXPL.search(s)
        if m: st[m.group(2).lower()] = {"kind":"char","len":int(m.group(3))}
        m = DECL_PACKED.search(s)
        if m:
            st[m.group(2).lower()] = {"kind":"packed","len":int(m.group(4)) if m.group(4) else None,
                                      "dec":int(m.group(6)) if m.group(6) else None}
        m = DECL_DEC_TYPE.search(s)
        if m:
            st[m.group(2).lower()] = {"kind":"dec","len":int(m.group(4)) if m.group(4) else None,
                                      "dec":int(m.group(6)) if m.group(6) else None}
        m = DECL_TYPE_GENERIC.search(s)
        if m:
            var, de = m.group(2).lower(), m.group(3)
            info = ddic_lookup_token(de)
            if info:
                st[var] = {"kind": ("amount" if info["dec"] is not None else "char"),
                           "len": info["len"], "dec": info["dec"], "ddic": de}
        # multi-line colon header
        mcol = DECL_HEADER_COLON.match(s)
        if not mcol:
            continue
        body = mcol.group(2)
        if body.endswith("."):
            body = body[:-1]
        for ent in smart_split_commas(body):
            em = DECL_ENTRY.match(ent)
            if not em:
                continue
            var = (em.group("var") or "").lower()
            if not var:
                continue
            if em.group("charlen"):
                st[var] = {"kind":"char","len":int(em.group("charlen"))}
                continue
            dtype = (em.group("dtype") or "").upper()
            if dtype in {"P","DEC"}:
                ln = int(em.group("len")) if em.group("len") else None
                dc = int(em.group("dec")) if em.group("dec") else None
                st[var] = {"kind":"packed" if dtype=="P" else "dec","len":ln,"dec":dc}
                continue
            ddic = (em.group("dtype") or em.group("like"))
            if ddic:
                info = ddic_lookup_token(ddic)
                if info:
                    st[var] = {"kind": ("amount" if info["dec"] is not None else "char"),
                               "len": info["len"], "dec": info["dec"], "ddic": ddic}
                else:
                    st.setdefault(var, {"kind":"char","len":None,"ddic":ddic})
    return st

# =========================
# Declaration index (cross-include, multi-line aware)
# =========================
class DeclSite:
    __slots__ = ("var","unit_idx","line","text")
    def __init__(self, var: str, unit_idx: int, line: int, text: str):
        self.var = var
        self.unit_idx = unit_idx
        self.line = line
        self.text = text

def build_declaration_index(units: List[Unit]) -> Dict[str, List[DeclSite]]:
    index: Dict[str, List[DeclSite]] = {}
    for uidx, u in enumerate(units):
        src = u.code or ""
        for stmt, s_off, _ in iter_statements_with_offsets(src):
            stripped = stmt.strip()
            # single-line patterns
            for pat in DECL_LINE_PATTERNS:
                m = pat.match(stripped)
                if m:
                    if pat.pattern.startswith(r"^\s*FIELD-SYMBOLS"):
                        var = (m.group(1) or "").lower()
                    else:
                        var = (m.group(2) or "").lower()
                    if var:
                        index.setdefault(var, []).append(DeclSite(var, uidx, line_of_offset(src, s_off), stripped))
                    break
            # multi-line colon block
            mcol = DECL_HEADER_COLON.match(stripped)
            if not mcol:
                continue
            body = mcol.group(2)
            if body.endswith("."):
                body = body[:-1]
            entries = smart_split_commas(body)
            # offset where 'body' starts inside 'stmt'
            body_rel_off = stripped.find(body)
            stmt_abs_start = s_off + (len(stmt) - len(stripped))
            rel = 0
            for ent in entries:
                if not ent:
                    continue
                subpos = body.find(ent, rel)
                if subpos < 0:
                    subpos = rel
                ent_abs_off = stmt_abs_start + body_rel_off + subpos
                rel = subpos + len(ent)
                em = DECL_ENTRY.match(ent)
                if not em:
                    continue
                var = (em.group("var") or "").lower()
                if not var:
                    continue
                line_no = line_of_offset(src, ent_abs_off)
                index.setdefault(var, []).append(DeclSite(var, uidx, line_no, ent.strip()))
    return index

# =========================
# AFLE sizing helpers
# =========================
def is_amount_like(symtab: Dict[str, Dict[str, Any]], expr: str) -> bool:
    expr = (expr or "").strip()
    dd = ddic_lookup_token(expr)
    if dd and dd["kind"] == "amount":
        return True
    mv = re.match(r"^(\w+)$", expr)
    if mv:
        info = symtab.get(mv.group(1).lower())
        if info and info["kind"] in {"amount","packed","dec"}:
            return True
    return bool(AMOUNT_NAME_HINT.search(expr))

def char_too_short(symtab: Dict[str, Dict[str, Any]], token: str, min_len: int = MIN_CHAR_FOR_AMOUNT) -> Optional[bool]:
    dd = ddic_lookup_token(token)
    if dd and dd["kind"] == "char":
        ln = dd.get("len") or 0
        return (ln < min_len) if ln else None
    info = symtab.get((token or "").lower())
    if not info: return None
    if info["kind"] == "char":
        ln = info.get("len") or 0
        return (ln < min_len) if ln else None
    return False

def dec_too_short(symtab: Dict[str, Dict[str, Any]], token: str, min_digits: int = MIN_DIGITS_FOR_AMOUNT) -> Optional[bool]:
    dd = ddic_lookup_token(token)
    if dd and dd["kind"] in {"amount","dec","packed"}:
        ln = dd.get("len") or 0
        return (ln < min_digits) if ln else None
    info = symtab.get((token or "").lower())
    if not info: return None
    if info["kind"] in {"packed","dec","amount"}:
        ln = info.get("len") or 0
        return (ln < min_digits) if ln else None
    return False

def _safe_severity_for_unknown():
    return "info" if SUPPRESS_UNKNOWN else "info"

# =========================
# Declaration mirrors
# =========================
class MirrorBucket(Dict[int, List[Dict[str, Any]]]):
    pass

def _emit_decl_mirrors(dest_token: str,
                       usage_issue_type: str,
                       usage_severity: str,
                       usage_unit: Unit,
                       usage_line: int,
                       decl_index: Dict[str, List[DeclSite]],
                       units: List[Unit],
                       mirror_buckets: MirrorBucket,
                       too_small: Optional[bool]):
    if not re.match(r"^[A-Za-z_]\w*$", dest_token or ""):
        return
    decls = decl_index.get(dest_token.lower()) or []
    if not decls:
        return
    # Only mirror when too_small is True, or (unknown and not suppressed)
    if too_small is None and SUPPRESS_UNKNOWN:
        return
    for d in decls:
        decl_unit = units[d.unit_idx]
        if too_small is True:
            msg = f"Declaration of '{dest_token}' appears too small for AFLE amounts used in {usage_unit.inc_name}/{usage_unit.name} at line {usage_line}."
            sev = "error"
            sug = "Widen the declared type to an AFLE-safe amount (e.g., P LENGTH 23 DECIMALS 2 or relevant DDIC element)."
            itype = "DeclarationAFLESizeRisk"
        else:
            msg = f"Declaration of '{dest_token}' may be insufficient for AFLE amounts used in {usage_unit.inc_name}/{usage_unit.name} at line {usage_line} (destination capacity unknown)."
            sev = _safe_severity_for_unknown()
            sug = "Verify declared type supports AFLE (≥23,2) or adjust DDIC element."
            itype = "DeclarationAFLECapacityUnknown"
        mirror = pack_decl_issue(
            decl_unit=decl_unit,
            decl_line=d.line,
            decl_text=d.text,
            issue_type=itype,
            message=msg,
            severity=sev,
            meta={"suggestion": sug}
        )
        mirror_buckets.setdefault(d.unit_idx, []).append(mirror)

# =========================
# Scanner (with decl-site mirrors)
# =========================
def _select_list_has_amounts(select_list: str, symtab: Dict[str, Dict[str, Any]]) -> bool:
    """
    Reduce false positives: only treat SELECT as amount-relevant if the select list
    includes any amount-like token (by name hint or DDIC).
    """
    if not select_list:
        return False
    # quick screen by keyword
    if AMOUNT_NAME_HINT.search(select_list):
        return True
    # try to find tokens like tab-field or bare names
    tokens = re.findall(r"[A-Za-z_]\w+(?:-[A-Za-z_]\w+)?", select_list)
    for t in tokens:
        if is_amount_like(symtab, t):
            return True
    return False

def scan_unit(unit_idx: int,
              unit: Unit,
              symtab: Dict[str, Dict[str, Any]],
              decl_index: Dict[str, List[DeclSite]],
              units: List[Unit],
              mirror_buckets: MirrorBucket) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    # 2) Concatenation — keep, but only when amount actually present
    for m in CONCATENATE_STMT.finditer(src):
        seg = m.group(0)
        any_amount = False
        for t in re.findall(r"[A-Za-z_]\w+(?:-[A-Za-z_]\w+)?", seg):
            if is_amount_like(symtab, t):
                any_amount = True
                break
        if any_amount:
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used in CONCATENATE; string ops ignore scale/precision.",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Avoid amount concatenation; format only for UI."}))
    for m in STRING_OP_AND.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, x.strip()) for x in re.findall(r"[A-Za-z_]\w+(?:-[A-Za-z_]\w+)?", seg)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used with '&&'.",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Avoid string ops with amounts; use formatting."}))
    for m in STRING_TEMPLATE.finditer(src):
        if is_amount_like(symtab, m.group(0)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used in string template.",
                                       "info", m.start(), m.end(),
                                       {"suggestion":"Templates OK for UI; avoid persisting templates."}))

    # 3) Offset/length
    for m in OFFSET_LEN.finditer(src):
        var, off, ln = m.group(1), int(m.group(2)), int(m.group(3))
        if is_amount_like(symtab, var):
            findings.append(pack_issue(unit, "OffsetLengthAccess",
                                       f"Offset/length on amount {var}: +{off}({ln}).",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Do not slice amounts; use numeric ops/formatting."}))

    # 4) Old move length conflict (MOVE ... TO ...)
    for m in MOVE_STMT.finditer(src):
        src_exp, dest = m.group(1).strip(), m.group(2)
        if not is_amount_like(symtab, src_exp):
            continue
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        if too_small:
            sev = "error"
        elif (cshort is None and dshort is None):
            if SUPPRESS_UNKNOWN:
                sev = None  # suppress
            else:
                sev = "info"
        else:
            sev = None  # destination is adequate or not char/dec
        if sev:
            usage = pack_issue(unit, "OldMoveLengthConflict",
                               f"Moving amount into {dest} " + ("(too small)." if too_small else "(destination capacity unknown)."),
                               sev, m.start(), m.end(),
                               {"suggestion":"Use AFLE-safe type (e.g., P LENGTH 23 DECIMALS 2 or DDIC amount)."})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, too_small if sev != "info" else None)

    # 4) Old move length conflict (= assignment)
    for m in ASSIGNMENT.finditer(src):
        dest, src_exp = m.group(1), m.group(2)
        if not is_amount_like(symtab, src_exp):
            continue
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        if too_small:
            sev = "error"
        elif (cshort is None and dshort is None):
            if SUPPRESS_UNKNOWN:
                sev = None
            else:
                sev = "info"
        else:
            sev = None
        if sev:
            usage = pack_issue(unit, "OldMoveLengthConflict",
                               f"Assignment from amount into {dest} " + ("(too small)." if too_small else "(type unknown)."),
                               sev, m.start(), m.end(),
                               {"suggestion":"Ensure destination is AFLE-safe (≥23,2) or adjust DDIC element."})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, too_small if sev != "info" else None)

    # 1) & 5) Compare length conflicts — only when other side is too small or literal (low sev)
    for m in IF_BLOCK.finditer(src):
        cond = m.group(1)
        for c in SIMPLE_CMP.finditer(cond):
            left, op, right = c.group(1), c.group(2), c.group(3)
            left_is_amt  = is_amount_like(symtab, left)
            right_is_amt = is_amount_like(symtab, right)
            if not (left_is_amt or right_is_amt):
                continue
            is_lit_token = lambda s: bool(re.match(r"^'.*'$", s)) or s.replace(".","",1).isdigit()
            other = right if left_is_amt else left
            if is_lit_token(other):
                # Literal compare -> informational only
                findings.append(pack_issue(unit, "CompareLengthConflict",
                                           "Comparison between amount and literal.",
                                           "info", m.start(), m.end(),
                                           {"suggestion":"Ensure literal semantics are intended; prefer comparing normalized numerics."}))
                continue
            # variable compare
            cshort = char_too_short(symtab, other)
            dshort = dec_too_short(symtab, other)
            too_small = (cshort is True) or (dshort is True)
            if too_small:
                sev = "error"
                usage = pack_issue(unit, "CompareLengthConflict",
                                   "Comparison with amount and short variable.",
                                   sev, m.start(), m.end(),
                                   {"suggestion":"Widen the non-amount/short side to AFLE-safe length or normalize both sides."})
                findings.append(usage)
                _emit_decl_mirrors(other, usage["issue_type"], usage["severity"], unit,
                                   usage["line"], decl_index, units, mirror_buckets, True)
            elif (cshort is None and dshort is None) and not SUPPRESS_UNKNOWN:
                findings.append(pack_issue(unit, "CompareLengthConflict",
                                           "Comparison with amount; other side capacity unknown.",
                                           "info", m.start(), m.end(),
                                           {"suggestion":"Verify the other side supports AFLE (≥23,2)."}))

    # Open SQL INTO — only if select list contains amount-like fields
    for m in SELECT_INTO.finditer(src):
        select_list = m.group(1)
        dest = m.group(2)
        if not _select_list_has_amounts(select_list, symtab):
            continue  # not an amount-relevant SELECT
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        if too_small:
            usage = pack_issue(unit, "OpenSQLTypeConflict",
                               f"SELECT list includes amounts; destination {dest} may overflow/truncate.",
                               "error", m.start(), m.end(),
                               {"suggestion":"Align {dest} to DB field type (AFLE-compliant P/DEC).",
                                "category":"Type conflicts in Open SQL"})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, True)
        elif (cshort is None and dshort is None) and not SUPPRESS_UNKNOWN:
            findings.append(pack_issue(unit, "OpenSQLTypeConflict",
                                       f"SELECT list includes amounts; {dest} capacity unknown.",
                                       "info", m.start(), m.end(),
                                       {"suggestion":"Verify destination vs DB; use AFLE-compliant type.",
                                        "category":"Type conflicts in Open SQL"}))

    # LOOP/READ INTO — unchanged logic but only mirror when too_small
    loop_read = re.compile(r"\b(LOOP\s+AT|READ\s+TABLE)\b.+\bINTO\b\s+(\w+)", re.IGNORECASE)
    for m in loop_read.finditer(src):
        wa = m.group(2)
        cshort = char_too_short(symtab, wa)
        dshort = dec_too_short(symtab, wa)
        too_small = (cshort is True) or (dshort is True)
        if too_small:
            usage = pack_issue(unit, "LoopReadTypeConflict",
                               f"Work area {wa} may be too small for AFLE amounts in row.",
                               "error", m.start(), m.end(),
                               {"suggestion":"Adjust work area to AFLE-compliant lengths.",
                                "category":"Type conflicts in LOOP/READ"})
            findings.append(usage)
            _emit_decl_mirrors(wa, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, True)

    # MOVE-CORRESPONDING — keep as warning
    for m in MOVE_CORRESP.finditer(src):
        findings.append(pack_issue(unit, "MoveCorrespondingRisk",
                                   "MOVE-CORRESPONDING may map extended amount to short field.",
                                   "warning", m.start(), m.end(),
                                   {"suggestion":"Align structures or use CORRESPONDING #( ... MAPPING ... )."}))

    # WRITE / WRITE TO — unchanged
    for m in WRITE_STMT.finditer(src):
        findings.append(pack_issue(unit, "ListWriteLayoutRisk",
                                   "WRITE list output may misalign due to AFLE output length.",
                                   "info", m.start(), m.end(),
                                   {"suggestion":"Specify explicit (len) or shift columns for classic lists.",
                                    "category":"WRITE statements (list output)"}))
    for m in WRITE_TO_STMT.finditer(src):
        target = m.group(2)
        cshort = char_too_short(symtab, target, min_len=MIN_CHAR_FOR_AMOUNT)
        if cshort is True:
            findings.append(pack_issue(unit, "WriteToTruncationRisk",
                                       f"WRITE TO target {target} may truncate AFLE amounts.",
                                       "error", m.start(), m.end(),
                                       {"suggestion":"Increase target CHAR length (≥{MIN_CHAR_FOR_AMOUNT}) or format properly.",
                                        "category":"WRITE TO"}))

    # Floating-point / exponentiation
    for m in FLOAT_TYPES_DECL.finditer(src):
        findings.append(pack_issue(unit, "FloatingArithmeticRisk",
                                   "Arithmetic with F/DECFLOAT16 may round long amounts.",
                                   "warning", m.start(), m.end(),
                                   {"suggestion":"Prefer DECFLOAT34 for AFLE-critical calculations.",
                                    "category":"Floating-point arithmetic"}))
    for m in EXPONENT_OP.finditer(src):
        findings.append(pack_issue(unit, "ExponentiationRoundingRisk",
                                   "'**' may cause rounding with long amounts.",
                                   "info", m.start(), m.end(),
                                   {"suggestion":"Avoid '**' with amounts or use DECFLOAT34-derived approach.",
                                    "category":"Floating-point arithmetic"}))

    # Arithmetic error handling cue
    if "CATCH SYSTEM-EXCEPTIONS" in src.upper():
        findings.append(pack_issue(unit, "ArithmeticErrorHandlingChange",
                                   "Overflow exceptions may no longer trigger after AFLE; update checks.",
                                   "info", 0, min(len(src), 1),
                                   {"suggestion":"Add boundary checks via CL_AFLE_MAX_MIN.",
                                    "category":"Arithmetic error handling"}))

    # Hardcoded constants
    for m in re.finditer(r"'[-]?9{9,}'", src):
        findings.append(pack_issue(unit, "HardcodedBoundaryConstant",
                                   "Hardcoded amount boundary likely too small post-AFLE.",
                                   "warning", m.start(), m.end(),
                                   {"suggestion":"Use CL_AFLE_MAX_MIN to derive boundaries.",
                                    "category":"Hardcoded min/max constants"}))

    # Data clusters & ALV
    for m in IMPORT_DB.finditer(src):
        findings.append(pack_issue(unit, "ImportPaddingMissing",
                                   "IMPORT FROM DATABASE without ACCEPTING PADDING may dump with AFLE data.",
                                   "error", m.start(), m.end(),
                                   {"suggestion":"Add ACCEPTING PADDING.",
                                    "category":"Data clusters (EXPORT/IMPORT)"}))
    for m in REUSE_ALV_LOAD.finditer(src):
        seg_end = src.find(".", m.start())
        seg = src[m.start(): seg_end if seg_end != -1 else m.end()]
        if not I_ACCEPT_PADDING.search(seg or ""):
            findings.append(pack_issue(unit, "ALVExtractPaddingMissing",
                                       "REUSE_ALV_EXTRACT_LOAD without I_ACCEPT_PADDING = 'X'.",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Pass I_ACCEPT_PADDING = 'X' for pre-AFLE extracts.",
                                        "category":"ALV extracts"}))

    # CDS/AMDP hints
    for m in CDS_CAST_DEC.finditer(src):
        findings.append(pack_issue(unit, "CDSCastLengthCheck",
                                   "CDS cast to abap.dec/curr with explicit length: verify AFLE-compliant length.",
                                   "info", m.start(), m.end(),
                                   {"suggestion":"Adjust cast lengths to support AFLE.",
                                    "category":"CDS/AMDP"}))
    for m in CDS_UNION.finditer(src):
        findings.append(pack_issue(unit, "CDSUnionLengthCheck",
                                   "CDS UNION: result length driven by first select list—verify amount lengths.",
                                   "info", m.start(), m.end(),
                                   {"suggestion":"Ensure first SELECT defines AFLE-compliant lengths.",
                                    "category":"CDS/AMDP"}))

    res = unit.model_dump()
    res["amount_findings"] = findings
    res["_scanner_mode"] = {
        "sap_online": False,
        "tavily_online": False,
        "http_client": None if _http is None else _http.__name__,
        "thresholds": {
            "MIN_CHAR_FOR_AMOUNT": MIN_CHAR_FOR_AMOUNT,
            "MIN_DIGITS_FOR_AMOUNT": MIN_DIGITS_FOR_AMOUNT,
            "DEFAULT_DECIMALS": DEFAULT_DECIMALS,
            "SUPPRESS_UNKNOWN": SUPPRESS_UNKNOWN,
        }
    }
    return res

# =========================
# Orchestrator
# =========================
def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    # 1) build symbol table from all sources (multi-line aware)
    flat_src = "\n".join(u.code or "" for u in units)
    symtab = build_symbol_table(flat_src)
    # 2) build declaration index (multi-line aware, line-accurate)
    decl_index = build_declaration_index(units)
    # 3) scan each unit; collect declaration mirrors per target unit
    mirror_buckets: Dict[int, List[Dict[str, Any]]] = {}
    results = []
    for idx, u in enumerate(units):
        results.append(scan_unit(idx, u, symtab, decl_index, units, mirror_buckets))
    # 4) inject declaration-site mirrors into the corresponding units’ findings
    for uidx, mirrors in mirror_buckets.items():
        if not mirrors:
            continue
        if uidx < len(results):
            results[uidx].setdefault("amount_findings", []).extend(mirrors)
    return results

# =========================
# API
# =========================
@app.post("/scan-amount")
async def scan_amount(units: List[Unit]):
    return analyze_units(units)

@app.post("/scan-amount")
async def scan_amount(units: List[Unit]):
    start_ts = datetime.utcnow().isoformat() + "Z"
    t0 = time.perf_counter()

    results = analyze_units(units)

    elapsed = time.perf_counter() - t0
    end_ts = datetime.utcnow().isoformat() + "Z"

    # Just print to server logs
    print(f"[SCAN-AMOUNT] Start: {start_ts}, End: {end_ts}, Elapsed: {elapsed:.6f} sec")

    return results

# To run:
# pip install fastapi uvicorn
# uvicorn app_amount_scan_webaware_decl_multiline:app --host 0.0.0.0 --port 8046
