# app_amount_scan_offline.py  (v2.4 – struct BEGIN/END tolerant; INCLUDE resolution; legacy P/C; hyphen tokens)
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os, re, json, time
from datetime import datetime
from pathlib import Path

# =========================
# Config (env)
# =========================
MIN_CHAR_FOR_AMOUNT    = int(os.getenv("MIN_CHAR_FOR_AMOUNT", "25"))   # suggested char width for formatted amounts
MIN_DIGITS_FOR_AMOUNT  = int(os.getenv("MIN_DIGITS_FOR_AMOUNT", "23")) # P/DEC total length to be AFLE-safe
DEFAULT_DECIMALS       = int(os.getenv("DEFAULT_DECIMALS", "2"))       # assume 2 decimals if unknown
SUPPRESS_UNKNOWN       = os.getenv("SUPPRESS_UNKNOWN", "false").lower() == "true"
ENABLE_GENERIC_WRITE_HINTS = os.getenv("ENABLE_GENERIC_WRITE_HINTS", "false").lower() == "true"
DDIC_PATH              = os.getenv("DDIC_PATH", "ddic.json")

# =========================
# App
# =========================
app = FastAPI(
    title="Amount Field Scanner (AFLE) — OFFLINE JSON DDIC",
    version="2.4"
)

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
# Offline DDIC registry
# =========================
class DDICRegistry:
    def __init__(self, path: str):
        self.de: Dict[str, Dict[str, Any]] = {}
        self.tf: Dict[str, Dict[str, Any]] = {}
        p = Path(path)
        if not p.exists():
            print(f"[DDIC] WARNING: {path} not found. All lookups will be unknown.")
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for k, v in (data.get("data_elements") or {}).items():
                self.de[k.upper()] = {
                    "len": int(v.get("len")) if v.get("len") is not None else None,
                    "dec": int(v.get("dec")) if v.get("dec") is not None else None,
                    "source": "json_de",
                }
            for k, v in (data.get("table_fields") or {}).items():
                self.tf[k.upper()] = {
                    "len": int(v.get("len")) if v.get("len") is not None else None,
                    "dec": int(v.get("dec")) if v.get("dec") is not None else None,
                    "source": "json_tf",
                }
            print(f"[DDIC] Loaded {len(self.de)} data elements, {len(self.tf)} table fields from {path}")
        except Exception as e:
            print(f"[DDIC] ERROR loading {path}: {e}")

    def data_element(self, name: str) -> Optional[Dict[str, Any]]:
        if not name:
            return None
        return self.de.get(name.upper())

    def table_field(self, tab: str, fld: str) -> Optional[Dict[str, Any]]:
        if not tab or not fld:
            return None
        key = f"{tab}-{fld}".upper()
        return self.tf.get(key)

DDIC = DDICRegistry(DDIC_PATH)

# =========================
# Regexes (scanner)
# =========================
# Single-line decls
DECL_CHAR_LEN_PAREN = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*\((\d+)\)\s*TYPE\s*C\b", re.IGNORECASE)
DECL_CHAR_LEN_EXPL  = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s*C\b[^.\n]*?\bLENGTH\b\s*(\d+)", re.IGNORECASE)
DECL_PACKED         = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+P\b[^.\n]*?(LENGTH\s+(\d+))?[^.\n]*?(DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_DEC_TYPE       = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+DEC\b[^.\n]*?(LENGTH\s+(\d+))?[^.\n]*?(DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_TYPE_GENERIC   = re.compile(r"\b(DATA|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+(\w+)\b", re.IGNORECASE)

# Token that supports component names (STRUCT-FIELD) or plain VAR
TOKEN = r"[A-Za-z_]\w*(?:-[A-Za-z_]\w+)?"

ASSIGNMENT  = re.compile(
    r"\b([A-Za-z_]\w*(?:-[A-Za-z_]\w+)?)\s*=\s*([^\.\n]+)\.",
    re.IGNORECASE
)
MOVE_STMT   = re.compile(
    r"\bMOVE\b\s+(.+?)\s+\bTO\b\s+([A-Za-z_]\w*(?:-[A-Za-z_]\w+)?)\s*\.",
    re.IGNORECASE
)
SELECT_INTO = re.compile(r"\bSELECT\b\s*(.+?)\bINTO\b\s+@?(\w+)\b", re.IGNORECASE | re.DOTALL)

IF_BLOCK    = re.compile(r"\bIF\b\s+(.+?)\.\s*", re.IGNORECASE | re.DOTALL)
SIMPLE_CMP  = re.compile(r"(\w+)\s*(=|<>|NE|EQ|LT|LE|GT|GE)\s*('?[\w\.\-]+'?|\w+)", re.IGNORECASE)

CONCATENATE_STMT = re.compile(r"\bCONCATENATE\b(.+?)\bINTO\b", re.IGNORECASE | re.DOTALL)
STRING_OP_AND    = re.compile(r"(.+?)\s*&&\s*(.+?)")
STRING_TEMPLATE  = re.compile(r"\|.*?\{[^}]*\}\|", re.IGNORECASE | re.DOTALL)
OFFSET_LEN       = re.compile(rf"\b({TOKEN})\s*\+\s*(\d+)\s*\(\s*(\d+)\s*\)", re.IGNORECASE)
WRITE_STMT       = re.compile(r"^\s*WRITE(\s*[:]?)(.+)", re.IGNORECASE | re.MULTILINE)
WRITE_TO_STMT    = re.compile(r"\bWRITE\s+(.+?)\bTO\b\s+(\w+)\b", re.IGNORECASE)
FLOAT_TYPES_DECL = re.compile(r"\bTYPE\s+(F|DECFLOAT16)\b", re.IGNORECASE)
EXPONENT_OP      = re.compile(r"\*\*")
MOVE_CORRESP     = re.compile(r"\bMOVE-CORRESPONDING\b", re.IGNORECASE)
IMPORT_DB        = re.compile(r"\bIMPORT\b.+\bFROM\b\s+DATABASE\b(?![^.]*ACCEPTING\s+PADDING)", re.IGNORECASE | re.DOTALL)
REUSE_ALV_LOAD   = re.compile(r"\bREUSE_ALV_EXTRACT_LOAD\b", re.IGNORECASE)
I_ACCEPT_PADDING = re.compile(r"I_ACCEPT_PADDING\s*=\s*'X'", re.IGNORECASE)
CDS_CAST_DEC     = re.compile(r"\bcast\s*\([^)]+as\s+abap\.(?:dec|curr)\s*\(\s*\d+\s*,\s*\d+\s*\)\s*\)", re.IGNORECASE)
CDS_UNION        = re.compile(r"\bselect\b.+\bunion\b", re.IGNORECASE | re.DOTALL)

# For declaration indexing (single-line)
DECL_LINE_PATTERNS = [
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s*:\s*(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s+(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*FIELD-SYMBOLS\s*<(\w+)>\b.*\.\s*$", re.IGNORECASE),
]

# --- FIX: Structure blocks — accept END OF with or without 'DATA:'; tolerate comma/newlines after BEGIN OF <name> ---
STRUCT_BLOCK_RE = re.compile(
    r"(?is)"
    r"^\s*(?:DATA\s*:)?\s*BEGIN\s+OF\s*(?:\r?\n\s*)?(?P<name>\w+)[^\n]*\n"
    r"(?P<body>.*?)"
    r"^\s*(?:DATA\s*:)?\s*END\s+OF\s+(?P=name)\s*\.",
    re.MULTILINE
)

# =========================
# Helpers
# =========================
def iter_statements_with_offsets(src: str):
    buf = []; start_off = 0
    for i, ch in enumerate(src):
        buf.append(ch)
        if ch == ".":
            stmt = "".join(buf)
            yield stmt, start_off, i + 1
            buf = []; start_off = i + 1
    if buf:
        yield "".join(buf), start_off, len(src)

def strip_trailing_dot(block: str) -> str:
    s = block.rstrip()
    return s[:-1] if s.endswith('.') else s

def parse_colon_body_entries(body: str) -> List[str]:
    body = strip_trailing_dot(body)
    parts, cur, in_q = [], [], False
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "'":
            in_q = not in_q
            cur.append(ch)
        elif ch == "," and not in_q:
            part = "".join(cur).strip()
            if part:
                parts.append(part)
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts

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
# Symbol table & lookups (offline only)
# =========================
STRUCT_INCLUDES: Dict[str, str] = {}   # lower(var) -> UPPER(included struct)

def ddic_lookup_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    t = token.strip().upper()

    # Table-field or variable-field (one hyphen)
    if "-" in t:
        a, b = t.split("-", 1)
        tf = DDIC.table_field(a, b)
        if tf:
            kind = "amount" if tf.get("dec") is not None else "char"
            return {"len": tf.get("len"), "dec": tf.get("dec"), "kind": kind, "source": "json_tf"}
        incl = STRUCT_INCLUDES.get(a.lower())
        if incl:
            tf = DDIC.table_field(incl, b)
            if tf:
                kind = "amount" if tf.get("dec") is not None else "char"
                return {"len": tf.get("len"), "dec": tf.get("dec"), "kind": kind, "source": f"include:{incl}"}
        return None

    de = DDIC.data_element(t)
    if de:
        kind = "amount" if de.get("dec") is not None else "char"
        return {"len": de.get("len"), "dec": de.get("dec"), "kind": kind, "source": de.get("source")}
    return None

def _parse_structure_components_into_symtab(full_src: str, st: Dict[str, Dict[str, Any]]):
    for sm in STRUCT_BLOCK_RE.finditer(full_src):
        struct = (sm.group("name") or "").lower()
        body   = sm.group("body") or ""

        # capture INCLUDE STRUCTURE
        for inc in re.finditer(r"\bINCLUDE\s+STRUCTURE\s+(\w+)\b", body, re.IGNORECASE):
            STRUCT_INCLUDES[struct] = inc.group(1).upper()

        # split components on lines/commas
        parts = re.split(r",\s*\n|\n", body)
        for raw in parts:
            ln = (raw or "").strip().rstrip(",.")
            if not ln or ln.upper().startswith("INCLUDE STRUCTURE"):
                continue

            # LIKE tab-field
            m_like = re.search(r"^(\w+)\s+LIKE\s+([A-Za-z_]\w*)-([A-Za-z_]\w*)\b", ln, re.IGNORECASE)
            if m_like:
                fld = m_like.group(1).lower()
                tab = m_like.group(2)
                col = m_like.group(3)
                info = DDIC.table_field(tab, col)
                if info:
                    kind = "amount" if info.get("dec") is not None else "char"
                    st[f"{struct}-{fld}"] = {"kind": kind, "len": info.get("len"), "dec": info.get("dec")}
                continue

            # legacy packed: field(n) TYPE p [DECIMALS d]
            m_p_legacy = re.search(r"^(\w+)\s*\((\d+)\)\s*TYPE\s+p\b(?:\s+DECIMALS\s+(\d+))?", ln, re.IGNORECASE)
            if m_p_legacy:
                fld = m_p_legacy.group(1).lower()
                ln_digits = int(m_p_legacy.group(2))
                dec = int(m_p_legacy.group(3)) if m_p_legacy.group(3) else None
                st[f"{struct}-{fld}"] = {"kind": "packed", "len": ln_digits, "dec": dec}
                continue

            # packed: field TYPE p [LENGTH n] [DECIMALS d]
            m_p = re.search(r"^(\w+)\s+TYPE\s+p\b(?:\s+LENGTH\s+(\d+))?(?:\s+DECIMALS\s+(\d+))?", ln, re.IGNORECASE)
            if m_p:
                fld = m_p.group(1).lower()
                ln_digits_or_bytes = int(m_p.group(2)) if m_p.group(2) else None
                dec = int(m_p.group(3)) if m_p.group(3) else None
                st[f"{struct}-{fld}"] = {"kind": "packed", "len": ln_digits_or_bytes, "dec": dec}
                continue

            # char legacy: field(n) TYPE c
            m_c = re.search(r"^(\w+)\s*\((\d+)\)\s*TYPE\s+c\b", ln, re.IGNORECASE)
            if m_c:
                fld = m_c.group(1).lower()
                ln_chars = int(m_c.group(2))
                st[f"{struct}-{fld}"] = {"kind": "char", "len": ln_chars}
                continue

def build_symbol_table(full_src: str) -> Dict[str, Dict[str, Any]]:
    st: Dict[str, Dict[str, Any]] = {}
    STRUCT_INCLUDES.clear()

    _parse_structure_components_into_symtab(full_src, st)

    for stmt, _, _ in iter_statements_with_offsets(full_src):
        s = stmt.strip()
        if not s:
            continue

        mcol = DECL_HEADER_COLON.match(s) if 'DECL_HEADER_COLON' in globals() else None
        if mcol:
            body = mcol.group("body")
            for ent in parse_colon_body_entries(body):
                em = DECL_ENTRY.match(ent)
                if not em:
                    continue
                var = (em.group("var") or "").lower()
                if not var:
                    continue

                if em.group("charlen"):
                    st[var] = {"kind": "char", "len": int(em.group("charlen"))}
                    continue

                dtype = (em.group("dtype") or "").upper()
                if dtype in {"P", "DEC"}:
                    ln = int(em.group("len")) if em.group("len") else None
                    dc = int(em.group("dec")) if em.group("dec") else None
                    st[var] = {"kind": "packed" if dtype == "P" else "dec", "len": ln, "dec": dc}
                    continue

                ddic = (em.group("dtype") or em.group("like"))
                if ddic:
                    info = ddic_lookup_token(ddic)
                    if info:
                        st[var] = {
                            "kind": ("amount" if info["dec"] is not None else "char"),
                            "len": info["len"],
                            "dec": info["dec"],
                            "ddic": ddic,
                        }
                    else:
                        st.setdefault(var, {"kind": "char", "len": None, "ddic": ddic})
            continue

        m = DECL_CHAR_LEN_PAREN.search(s)
        if m:
            st[m.group(2).lower()] = {"kind": "char", "len": int(m.group(3))}
            continue

        m = DECL_CHAR_LEN_EXPL.search(s)
        if m:
            st[m.group(2).lower()] = {"kind": "char", "len": int(m.group(3))}
            continue

        m = DECL_PACKED.search(s)
        if m:
            st[m.group(2).lower()] = {
                "kind": "packed",
                "len": int(m.group(4)) if m.group(4) else None,
                "dec": int(m.group(6)) if m.group(6) else None,
            }
            continue

        m = DECL_DEC_TYPE.search(s)
        if m:
            st[m.group(2).lower()] = {
                "kind": "dec",
                "len": int(m.group(4)) if m.group(4) else None,
                "dec": int(m.group(6)) if m.group(6) else None,
            }
            continue

        m = DECL_TYPE_GENERIC.search(s)
        if m:
            var, de = m.group(2).lower(), m.group(3)
            info = ddic_lookup_token(de)
            if info:
                st[var] = {
                    "kind": ("amount" if info["dec"] is not None else "char"),
                    "len": info["len"],
                    "dec": info["dec"],
                    "ddic": de,
                }

    return st

# =========================
# Declaration index (colon-first)
# =========================
class DeclSite:
    __slots__ = ("var","unit_idx","line","text")
    def __init__(self, var: str, unit_idx: int, line: int, text: str):
        self.var = var; self.unit_idx = unit_idx; self.line = line; self.text = text

def build_declaration_index(units: List[Unit]) -> Dict[str, List[DeclSite]]:
    index: Dict[str, List[DeclSite]] = {}

    for uidx, u in enumerate(units):
        src = u.code or ""
        for stmt, s_off, _ in iter_statements_with_offsets(src):
            stripped = stmt.strip()
            if not stripped:
                continue

            mcol = DECL_HEADER_COLON.match(stripped)
            if mcol:
                body = mcol.group("body")
                body_rel_off = stripped.find(body)
                stmt_abs_start = s_off + (len(stmt) - len(stripped))
                rel = 0
                for ent in parse_colon_body_entries(body):
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
                continue

            for pat in DECL_LINE_PATTERNS:
                m = pat.match(stripped)
                if m:
                    if pat.pattern.startswith(r"^\s*FIELD-SYMBOLS"):
                        var = (m.group(1) or "").lower()
                    else:
                        var = (m.group(2) or "").lower()
                    if var:
                        index.setdefault(var, []).append(
                            DeclSite(var, uidx, line_of_offset(src, s_off), stripped)
                        )
                    break

    return index

# =========================
# AFLE helpers
# =========================
def is_amount_like(symtab: Dict[str, Dict[str, Any]], expr: str) -> bool:
    expr = (expr or "").strip()
    dd = ddic_lookup_token(expr)
    if dd and dd["kind"] == "amount":
        return True
    mv = re.match(rf"^({TOKEN})$", expr)
    if mv:
        info = symtab.get(mv.group(1).lower())
        if info and info["kind"] in {"amount","packed","dec"}:
            return True
    return False

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

class MirrorBucket(Dict[int, List[Dict[str, Any]]]): pass

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
            sev = "info"
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

def _select_list_has_amounts(select_list: str, symtab: Dict[str, Dict[str, Any]]) -> bool:
    if not select_list:
        return False
    tokens = re.findall(r"[A-Za-z_]\w+(?:-[A-Za-z_]\w+)?", select_list)
    for t in tokens:
        if is_amount_like(symtab, t):
            return True
    return False

# =========================
# Scanner
# =========================
def scan_unit(unit_idx: int,
              unit: Unit,
              symtab: Dict[str, Dict[str, Any]],
              decl_index: Dict[str, List[DeclSite]],
              units: List[Unit],
              mirror_buckets: MirrorBucket) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    # Concatenation / string ops
    for m in CONCATENATE_STMT.finditer(src):
        seg = m.group(0)
        any_amount = any(is_amount_like(symtab, t) for t in re.findall(r"[A-Za-z_]\w+(?:-[A-Za-z_]\w+)?", seg))
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
        if any(is_amount_like(symtab, t) for t in re.findall(r"[A-Za-z_]\w+(?:-[A-Za-z_]\w+)?", m.group(0))):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used in string template.",
                                       "info", m.start(), m.end(),
                                       {"suggestion":"Templates OK for UI; avoid persisting templates."}))

    # Offset/length slicing
    for m in OFFSET_LEN.finditer(src):
        var, off, ln = m.group(1), int(m.group(2)), int(m.group(3))
        if is_amount_like(symtab, var):
            findings.append(pack_issue(unit, "OffsetLengthAccess",
                                       f"Offset/length on amount {var}: +{off}({ln}).",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Do not slice amounts; use numeric ops/formatting."}))

    # MOVE ... TO ...
    for m in MOVE_STMT.finditer(src):
        src_exp, dest = m.group(1).strip(), m.group(2)
        if not is_amount_like(symtab, src_exp):
            continue
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        sev = "error" if too_small else (None if SUPPRESS_UNKNOWN else "info")
        if sev:
            usage = pack_issue(unit, "OldMoveLengthConflict",
                               f"Moving amount into {dest} " + ("(too small)." if too_small else "(destination capacity unknown)."),
                               sev, m.start(), m.end(),
                               {"suggestion":"Use AFLE-safe type (e.g., P LENGTH 23 DECIMALS 2 or DDIC amount)."})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, True if too_small else None)

    # Assignment =
    for m in ASSIGNMENT.finditer(src):
        dest, src_exp = m.group(1), m.group(2)
        if not is_amount_like(symtab, src_exp):
            continue
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        sev = "error" if too_small else (None if SUPPRESS_UNKNOWN else "info")
        if sev:
            usage = pack_issue(unit, "OldMoveLengthConflict",
                               f"Assignment from amount into {dest} " + ("(too small)." if too_small else "(type unknown)."),
                               sev, m.start(), m.end(),
                               {"suggestion":"Ensure destination is AFLE-safe (≥23,2) or adjust DDIC element."})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, True if too_small else None)

    # IF comparisons
    for m in IF_BLOCK.finditer(src):
        cond = m.group(1)
        for c in SIMPLE_CMP.finditer(cond):
            left, _, right = c.group(1), c.group(2), c.group(3)
            left_is_amt  = is_amount_like(symtab, left)
            right_is_amt = is_amount_like(symtab, right)
            if not (left_is_amt or right_is_amt):
                continue
            is_lit = bool(re.match(r"^'.*'$", right)) or right.replace(".","",1).isdigit() \
                     or bool(re.match(r"^'.*'$", left))  or left.replace(".","",1).isdigit()
            other = right if left_is_amt else left
            if is_lit:
                findings.append(pack_issue(unit, "CompareLengthConflict",
                                           "Comparison between amount and literal.",
                                           "info", m.start(), m.end(),
                                           {"suggestion":"Ensure literal semantics are intended; prefer numeric compares."}))
                continue
            cshort = char_too_short(symtab, other)
            dshort = dec_too_short(symtab, other)
            too_small = (cshort is True) or (dshort is True)
            if too_small:
                usage = pack_issue(unit, "CompareLengthConflict",
                                   "Comparison with amount and short variable.",
                                   "error", m.start(), m.end(),
                                   {"suggestion":"Widen non-amount side to AFLE-safe length or normalize both sides."})
                findings.append(usage)
                if re.match(r"^[A-Za-z_]\w*$", other or ""):
                    _emit_decl_mirrors(other, usage["issue_type"], usage["severity"], unit,
                                       usage["line"], decl_index, units, mirror_buckets, True)
            elif (cshort is None and dshort is None) and not SUPPRESS_UNKNOWN:
                findings.append(pack_issue(unit, "CompareLengthConflict",
                                           "Comparison with amount; other side capacity unknown.",
                                           "info", m.start(), m.end(),
                                           {"suggestion":"Verify the other side supports AFLE (≥23,2)."}))

    # SELECT ... INTO
    for m in SELECT_INTO.finditer(src):
        select_list = m.group(1); dest = m.group(2)
        if not _select_list_has_amounts(select_list, symtab):
            continue
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        if too_small:
            usage = pack_issue(unit, "OpenSQLTypeConflict",
                               f"SELECT list includes amounts; destination {dest} may overflow/truncate.",
                               "error", m.start(), m.end(),
                               {"suggestion":"Align destination to DB field type (AFLE-compliant P/DEC).",
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

    # LOOP/READ INTO
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

    # MOVE-CORRESPONDING (generic)
    for m in MOVE_CORRESP.finditer(src):
        findings.append(pack_issue(unit, "MoveCorrespondingRisk",
                                   "MOVE-CORRESPONDING may map extended amount to short field.",
                                   "warning", m.start(), m.end(),
                                   {"suggestion":"Align structures or use CORRESPONDING #( ... MAPPING ... )."}))

    # WRITE generic hints (optional)
    if ENABLE_GENERIC_WRITE_HINTS:
        for m in WRITE_STMT.finditer(src):
            findings.append(pack_issue(unit, "ListWriteLayoutRisk",
                                       "WRITE list output may misalign due to AFLE output length.",
                                       "info", m.start(), m.end(),
                                       {"suggestion":"Specify explicit (len) or shift columns for classic lists.",
                                        "category":"WRITE statements (list output)"}))
    # WRITE TO <target>
    for m in WRITE_TO_STMT.finditer(src):
        target = m.group(2)
        cshort = char_too_short(symtab, target, min_len=MIN_CHAR_FOR_AMOUNT)
        if cshort is True:
            findings.append(pack_issue(unit, "WriteToTruncationRisk",
                                       f"WRITE TO target {target} may truncate AFLE amounts.",
                                       "error", m.start(), m.end(),
                                       {"suggestion":f"Increase target CHAR length (≥{MIN_CHAR_FOR_AMOUNT}) or format properly.",
                                        "category":"WRITE TO"}))

    # Floating/exponent (advisory)
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

    # CDS/AMDP
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
        "http_client": None,
        "thresholds": {
            "MIN_CHAR_FOR_AMOUNT": MIN_CHAR_FOR_AMOUNT,
            "MIN_DIGITS_FOR_AMOUNT": MIN_DIGITS_FOR_AMOUNT,
            "DEFAULT_DECIMALS": DEFAULT_DECIMALS,
            "SUPPRESS_UNKNOWN": SUPPRESS_UNKNOWN,
            "ENABLE_GENERIC_WRITE_HINTS": ENABLE_GENERIC_WRITE_HINTS,
        },
        "ddic_path": str(DDIC_PATH),
        "ddic_loaded": True if (DDIC.de or DDIC.tf) else False
    }
    return res

# =========================
# Orchestrator
# =========================
def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    flat_src = "\n".join(u.code or "" for u in units)
    symtab = build_symbol_table(flat_src)
    decl_index = build_declaration_index(units)
    mirror_buckets: Dict[int, List[Dict[str, Any]]] = {}
    results = []
    for idx, u in enumerate(units):
        results.append(scan_unit(idx, u, symtab, decl_index, units, mirror_buckets))
    for uidx, mirrors in mirror_buckets.items():
        if mirrors and uidx < len(results):
            results[uidx].setdefault("amount_findings", []).extend(mirrors)
    return results

# =========================
# API
# =========================
@app.post("/scan-amount")
async def scan_amount(units: List[Unit]):
    start_ts = datetime.utcnow().isoformat() + "Z"
    t0 = time.perf_counter()
    results = analyze_units(units)
    elapsed = time.perf_counter() - t0
    end_ts = datetime.utcnow().isoformat() + "Z"
    return results

@app.get("/health")
def health():
    return {
        "ok": True,
        "ddic_loaded": True if (DDIC.de or DDIC.tf) else False,
        "ddic_path": str(DDIC_PATH),
        "counts": {"data_elements": len(DDIC.de), "table_fields": len(DDIC.tf)},
        "thresholds": {
            "MIN_CHAR_FOR_AMOUNT": MIN_CHAR_FOR_AMOUNT,
            "MIN_DIGITS_FOR_AMOUNT": MIN_DIGITS_FOR_AMOUNT,
            "DEFAULT_DECIMALS": DEFAULT_DECIMALS,
            "SUPPRESS_UNKNOWN": SUPPRESS_UNKNOWN,
            "ENABLE_GENERIC_WRITE_HINTS": ENABLE_GENERIC_WRITE_HINTS,
        }
    }
