# app_afle_amount_scan.py
# Offline AFLE (SAP Note 2610650) amount scanner using ddic.json
# - Detects assignments/moves/selects where amount-like fields (e.g., BSEG-DMBTR, RTAX1U15-WMWST)
#   flow into too-short numeric/char destinations
# - Resolves local structure components and INCLUDE STRUCTURE mappings
# - Emits declaration-site mirrors so you can fix the declaration where it's defined
#
# Environment vars (optional):
#   DDIC_PATH=ddic.json
#   MIN_DIGITS_FOR_AMOUNT=23
#   MIN_CHAR_FOR_AMOUNT=25
#   SUPPRESS_UNKNOWN=false          (if true, suppress "unknown dest type" infos)
#   DEBUG_SYMTAB=false              (if true, print the symbol table once per run)

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
import os, json, re, time

# =========================
# Config (env)
# =========================
DDIC_PATH               = os.getenv("DDIC_PATH", "ddic.json")
MIN_DIGITS_FOR_AMOUNT   = int(os.getenv("MIN_DIGITS_FOR_AMOUNT", "23"))
MIN_CHAR_FOR_AMOUNT     = int(os.getenv("MIN_CHAR_FOR_AMOUNT", "25"))
SUPPRESS_UNKNOWN        = os.getenv("SUPPRESS_UNKNOWN", "false").lower() == "true"
DEBUG_SYMTAB            = os.getenv("DEBUG_SYMTAB", "false").lower() in {"1","true","yes","y"}

# =========================
# App
# =========================
app = FastAPI(
    title="AFLE Amount Scanner (offline ddic.json)",
    version="1.0"
)

# =========================
# Models
# =========================
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: str
    amount_findings: Optional[List[Finding]] = None  # output

# =========================
# Offline DDIC registry
# =========================
class DDICRegistry:
    def __init__(self, path: str):
        self.de: Dict[str, Dict[str, Any]] = {}
        self.tf: Dict[str, Dict[str, Any]] = {}
        p = Path(path)
        if not p.exists():
            print(f"[DDIC] WARNING: {path} not found. All lookups unknown.")
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
        if not name: return None
        return self.de.get(name.upper())

    def table_field(self, tabfld: str) -> Optional[Dict[str, Any]]:
        # tabfld must be "TAB-FLD" in uppercase (already combined)
        if not tabfld: return None
        return self.tf.get(tabfld.upper())

DDIC = DDICRegistry(DDIC_PATH)

# =========================
# Regexes (declarations & usage)
# =========================
# Tokens: VAR or STRUCT-FIELD
TOKEN = r"[A-Za-z_]\w*(?:-[A-Za-z_]\w+)?"

# --- Declarations (single-line) ---
DECL_CHAR_LEN_PAREN = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*\((\d+)\)\s*TYPE\s*C\b", re.IGNORECASE)
DECL_CHAR_LEN_EXPL  = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s*C\b[^.\n]*?\bLENGTH\b\s*(\d+)", re.IGNORECASE)
DECL_PACKED         = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+P\b[^.\n]*?(?:LENGTH\s+(\d+))?[^.\n]*?(?:DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_DEC_TYPE       = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+DEC\b[^.\n]*?(?:LENGTH\s+(\d+))?[^.\n]*?(?:DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_TYPE_GENERIC   = re.compile(r"\b(DATA|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s+(?:TYPE|LIKE)\s+(\w+)\b", re.IGNORECASE)

# --- Colon-style header + entries ---
DECL_HEADER_COLON = re.compile(
    r"""(?imxs)
    ^\s*
    (DATA|STATICS|CONSTANTS|PARAMETERS)
    \s*:\s*
    (?P<body> .*?)
    \.\s*(?:\"[^\n]*)?$       # end at dot, optional eol comment
    """
)
DECL_ENTRY = re.compile(
    r"^\s*(?P<var>\w+)\s*(?:(?:TYPE|LIKE)\s+(?P<dtype>\w+(?:-\w+)?)(?:\s+LENGTH\s+(?P<len>\d+))?(?:\s+DECIMALS\s+(?P<dec>\d+))?|\((?P<charlen>\d+)\)\s*TYPE\s*C)?",
    re.IGNORECASE
)

# --- Structure blocks: chained and classic ---
STRUCT_BLOCK_RE = re.compile(
    r"""(?isx)
    ^\s*DATA\s*:\s*BEGIN\s+OF\s+(\w+)[^.\n]*\.\s*   # DATA: BEGIN OF s .
    (?P<body> .*?)
    ^\s*DATA\s*:\s*END\s+OF\s+\1\s*\.\s*            # DATA: END OF s .
    """, re.MULTILINE
)

CLASSIC_STRUCT_BLOCK_RE = re.compile(
    r"""(?isx)
    ^\s*DATA\s*:\s*BEGIN\s+OF\s+(?P<name>\w+)[^.\n]*\.\s*   # DATA: BEGIN OF <name>.
    (?P<body> .*?)                                          # body
    ^\s*DATA\s*:\s*END\s+OF\s+(?P=name)\s*\.\s*             # DATA: END OF <name>.
    """, re.MULTILINE,
)

# --- Usage patterns ---
ASSIGNMENT  = re.compile(rf"\b({TOKEN})\s*=\s*([^\.\n]+)\.", re.IGNORECASE)
MOVE_STMT   = re.compile(rf"\bMOVE\b\s+(.+?)\s+\bTO\b\s+({TOKEN})\s*\.", re.IGNORECASE)
SELECT_INTO = re.compile(r"\bSELECT\b\s*(.+?)\bINTO\b\s+@?(\w+)\b", re.IGNORECASE | re.DOTALL)
IF_BLOCK    = re.compile(r"\bIF\b\s+(.+?)\.\s*", re.IGNORECASE | re.DOTALL)
SIMPLE_CMP  = re.compile(rf"({TOKEN})\s*(=|<>|NE|EQ|LT|LE|GT|GE)\s*('?[\w\.\-]+'?|{TOKEN})", re.IGNORECASE)

CONCATENATE_STMT = re.compile(r"\bCONCATENATE\b(.+?)\bINTO\b", re.IGNORECASE | re.DOTALL)
STRING_OP_AND    = re.compile(r"(.+?)\s*&&\s*(.+?)")
STRING_TEMPLATE  = re.compile(r"\|.*?\{[^}]*\}\|", re.IGNORECASE | re.DOTALL)

OFFSET_LEN       = re.compile(rf"\b({TOKEN})\s*\+\s*(\d+)\s*\(\s*(\d+)\s*\)", re.IGNORECASE)
WRITE_TO_STMT    = re.compile(r"\bWRITE\s+(.+?)\bTO\b\s+(\w+)\b", re.IGNORECASE)

# =========================
# Helpers
# =========================
def iter_statements_with_offsets(src: str):
    """Yield (statement_text, start_offset, end_offset) for each '.'-terminated statement."""
    buf = []; start_off = 0
    for i, ch in enumerate(src):
        buf.append(ch)
        if ch == ".":
            stmt = "".join(buf)
            yield stmt, start_off, i + 1
            buf = []; start_off = i + 1
    if buf:
        yield "".join(buf), start_off, len(src)

def smart_split_commas(s: str) -> List[str]:
    parts, cur, in_q = [], [], False
    for ch in s:
        if ch == "'":
            in_q = not in_q; cur.append(ch)
        elif ch == "," and not in_q:
            parts.append("".join(cur).strip()); cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]

def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet(text: str, start: int, end: int) -> str:
    s = max(0, start - 60); e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def pack_issue(unit: Unit, issue_type, message, severity, start, end, suggestion, meta=None):
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
        "suggestion": suggestion or "",
        "snippet": snippet(src, start, end),
        "meta": meta or {}
    }

def pack_decl_issue(decl_unit: Unit, decl_line: int, decl_text: str,
                    issue_type: str, message: str, severity: str, suggestion: str, meta=None):
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
        "suggestion": suggestion or "",
        "snippet": decl_text,
        "meta": meta or {}
    }

# =========================
# Symbol table & DDIC resolution
# =========================
STRUCT_INCLUDE_MAP: Dict[str, str] = {}   # local_struct(lower) -> DDIC struct (UPPER)

def ddic_lookup_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Resolve DDIC info for:
      - Table field "TAB-FLD" (uppercased)
      - Data element "DE" (uppercased)
    """
    if not token: return None
    t = token.strip().upper()

    # direct TAB-FLD?
    if "-" in t:
        info = DDIC.table_field(t)
        if info:  # {"len":..., "dec":...}
            kind = "amount" if info.get("dec") is not None else "char"
            return {"len": info.get("len"), "dec": info.get("dec"), "kind": kind, "source": info.get("source")}

        # local_struct-field mapped to DDIC struct?
        parts = t.split("-")
        if len(parts) == 2:
            local_struct = parts[0].lower()
            comp = parts[1]
            mapped = STRUCT_INCLUDE_MAP.get(local_struct)
            if mapped:
                info2 = DDIC.table_field(f"{mapped}-{comp}")
                if info2:
                    kind = "amount" if info2.get("dec") is not None else "char"
                    return {"len": info2.get("len"), "dec": info2.get("dec"), "kind": kind, "source": info2.get("source")}
        return None

    # data element?
    de = DDIC.data_element(t)
    if de:
        kind = "amount" if de.get("dec") is not None else "char"
        return {"len": de.get("len"), "dec": de.get("dec"), "kind": kind, "source": de.get("source")}
    return None

def _parse_struct_block(name: str, body: str, symtab: Dict[str, Dict[str, Any]]):
    struct = (name or "").lower()
    body = body or ""
    # record INCLUDE STRUCTURE for mapping
    for inc in re.finditer(r"\bINCLUDE\s+STRUCTURE\s+(\w+)\b", body, re.IGNORECASE):
        STRUCT_INCLUDE_MAP[struct] = inc.group(1).upper()

    # normalize inner leading "DATA:" prefixes
    body_norm = re.sub(r"(?mi)^\s*DATA\s*:\s*", "", body)

    # Split by commas/newlines; tolerate comma-chained components
    for raw in re.split(r",\s*\n|\n|,", body_norm):
        ln = (raw or "").strip().rstrip(",.")
        if not ln: continue
        if re.search(r"\bINCLUDE\s+STRUCTURE\b", ln, re.IGNORECASE):
            continue

        # field LIKE TAB-FLD
        m_like = re.search(r"^(\w+)\s+(?:LIKE|TYPE)\s+([A-Za-z_]\w*)-([A-Za-z_]\w*)\b", ln, re.IGNORECASE)
        if m_like:
            fld = m_like.group(1).lower()
            tab = m_like.group(2).upper()
            col = m_like.group(3).upper()
            info = DDIC.table_field(f"{tab}-{col}")
            if info:
                kind = "amount" if info.get("dec") is not None else "char"
                symtab[f"{struct}-{fld}"] = {"kind": kind, "len": info.get("len"), "dec": info.get("dec")}
            continue

        # legacy packed: field(n) TYPE p [DECIMALS d]
        m_p_legacy = re.search(r"^(\w+)\s*\((\d+)\)\s*TYPE\s+p\b(?:\s+DECIMALS\s+(\d+))?", ln, re.IGNORECASE)
        if m_p_legacy:
            fld = m_p_legacy.group(1).lower()
            ln_digits = int(m_p_legacy.group(2))
            dec = int(m_p_legacy.group(3)) if m_p_legacy.group(3) else None
            symtab[f"{struct}-{fld}"] = {"kind": "packed", "len": ln_digits, "dec": dec}
            continue

        # normal packed: field TYPE p [LENGTH n] [DECIMALS d]
        m_p = re.search(r"^(\w+)\s+TYPE\s+p\b(?:\s+LENGTH\s+(\d+))?(?:\s+DECIMALS\s+(\d+))?", ln, re.IGNORECASE)
        if m_p:
            fld = m_p.group(1).lower()
            ln_digits = int(m_p.group(2)) if m_p.group(2) else None
            dec = int(m_p.group(3)) if m_p.group(3) else None
            symtab[f"{struct}-{fld}"] = {"kind": "packed", "len": ln_digits, "dec": dec}
            continue

        # char legacy: field(n) TYPE c
        m_c = re.search(r"^(\w+)\s*\((\d+)\)\s*TYPE\s+c\b", ln, re.IGNORECASE)
        if m_c:
            fld = m_c.group(1).lower()
            ln_chars = int(m_c.group(2))
            symtab[f"{struct}-{fld}"] = {"kind": "char", "len": ln_chars}
            continue

def build_symbol_table(full_src: str) -> Dict[str, Dict[str, Any]]:
    """
    Build a symbol table of declarations (var or struct-field) with kind/len/dec.
    Sources:
      - DATA/STATICS/PARAMETERS single-line declarations
      - Colon-style headers (multi-entry)
      - Structure blocks, both "chained" and "classic", including INCLUDE STRUCTURE mapping
    """
    STRUCT_INCLUDE_MAP.clear()
    st: Dict[str, Dict[str, Any]] = {}

    # Structure blocks first
    for m in STRUCT_BLOCK_RE.finditer(full_src):
        name = m.group(1); body = m.group("body")
        _parse_struct_block(name, body, st)
    for m in CLASSIC_STRUCT_BLOCK_RE.finditer(full_src):
        name = m.group("name"); body = m.group("body")
        _parse_struct_block(name, body, st)

    # Other declarations (single-line + colon body)
    for stmt, _, _ in iter_statements_with_offsets(full_src):
        s = stmt.strip()
        if not s: continue

        # single-line patterns
        m = DECL_CHAR_LEN_PAREN.search(s)
        if m: st[m.group(2).lower()] = {"kind": "char", "len": int(m.group(3))}
        m = DECL_CHAR_LEN_EXPL.search(s)
        if m: st[m.group(2).lower()] = {"kind": "char", "len": int(m.group(3))}
        m = DECL_PACKED.search(s)
        if m:
            st[m.group(2).lower()] = {
                "kind": "packed",
                "len": int(m.group(3)) if m.group(3) else None,
                "dec": int(m.group(4)) if m.group(4) else None,
            }
        m = DECL_DEC_TYPE.search(s)
        if m:
            st[m.group(2).lower()] = {
                "kind": "dec",
                "len": int(m.group(3)) if m.group(3) else None,
                "dec": int(m.group(4)) if m.group(4) else None,
            }
        m = DECL_TYPE_GENERIC.search(s)
        if m:
            var, de = m.group(2).lower(), m.group(3)
            info = ddic_lookup_token(de)
            if info:
                st[var] = {"kind": ("amount" if info["dec"] is not None else "char"),
                           "len": info.get("len"), "dec": info.get("dec"), "ddic": de}

        # colon-style (multi-entry) — parsed after single-line so it can overwrite
        mcol = DECL_HEADER_COLON.match(s)
        if mcol:
            body = mcol.group("body")
            body = body[:-1] if body.endswith(".") else body
            for ent in smart_split_commas(body):
                em = DECL_ENTRY.match(ent)
                if not em: continue
                var = (em.group("var") or "").lower()
                if not var: continue

                if em.group("charlen"):
                    st[var] = {"kind": "char", "len": int(em.group("charlen"))}
                    continue

                dtype = (em.group("dtype") or "").upper()
                ln    = int(em.group("len")) if em.group("len") else None
                dec   = int(em.group("dec")) if em.group("dec") else None

                # LIKE/TYPE to TAB-FLD or DE
                info = ddic_lookup_token(dtype) if dtype else None
                if info:
                    st[var] = {"kind": ("amount" if info["dec"] is not None else "char"),
                               "len": info.get("len"), "dec": info.get("dec"), "ddic": dtype}
                    continue

                # Explicit P/DEC via colon entry
                if dtype == "P":
                    st[var] = {"kind": "packed", "len": ln, "dec": dec}
                elif dtype == "DEC":
                    st[var] = {"kind": "dec", "len": ln, "dec": dec}
                elif dtype == "C" and ln is not None:
                    st[var] = {"kind": "char", "len": ln}

    if DEBUG_SYMTAB:
        print("\n[DEBUG] Symbol table (amount-related & others):")
        for k in sorted(st.keys()):
            print(f"  {k} -> {st[k]}")
        if STRUCT_INCLUDE_MAP:
            print("[DEBUG] INCLUDE STRUCTURE map:")
            for k,v in STRUCT_INCLUDE_MAP.items():
                print(f"  {k} -> {v}")
        print("")

    return st

# =========================
# Declaration index
# =========================
class DeclSite:
    __slots__ = ("var","unit_idx","line","text")
    def __init__(self, var: str, unit_idx: int, line: int, text: str):
        self.var = var; self.unit_idx = unit_idx; self.line = line; self.text = text

DECL_LINE_PATTERNS = [
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s*:\s*(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s+(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*FIELD-SYMBOLS\s*<(\w+)>\b.*\.\s*$", re.IGNORECASE),
]

def build_declaration_index(units: List[Unit]) -> Dict[str, List[DeclSite]]:
    idx: Dict[str, List[DeclSite]] = {}
    for uidx, u in enumerate(units):
        src = u.code or ""
        for stmt, s_off, _ in iter_statements_with_offsets(src):
            stripped = stmt.strip()
            if not stripped: continue

            # single-line
            for pat in DECL_LINE_PATTERNS:
                m = pat.match(stripped)
                if m:
                    var = (m.group(1) if pat.pattern.startswith(r"^\s*FIELD-SYMBOLS") else m.group(2)).lower()
                    if var:
                        idx.setdefault(var, []).append(DeclSite(var, uidx, line_of_offset(src, s_off), stripped))
                    break

            # colon-style per-entry
            mcol = DECL_HEADER_COLON.match(stripped)
            if not mcol:
                continue
            body = mcol.group("body")
            if body.endswith("."): body = body[:-1]
            body_rel_off = stripped.find(body)
            stmt_abs_start = s_off + (len(stmt) - len(stripped))
            rel = 0
            for ent in smart_split_commas(body):
                if not ent: continue
                subpos = body.find(ent, rel)
                if subpos < 0: subpos = rel
                ent_abs_off = stmt_abs_start + body_rel_off + subpos
                rel = subpos + len(ent)
                em = DECL_ENTRY.match(ent)
                if not em: continue
                var = (em.group("var") or "").lower()
                if not var: continue
                idx.setdefault(var, []).append(
                    DeclSite(var, uidx, line_of_offset(src, ent_abs_off), ent.strip())
                )
    return idx

# =========================
# AFLE helpers
# =========================
def is_amount_like(symtab: Dict[str, Dict[str, Any]], expr: str) -> bool:
    expr = (expr or "").strip()
    # DDIC lookup of explicit TAB-FLD/DE or mapped struct-field
    dd = ddic_lookup_token(expr)
    if dd and dd["kind"] == "amount":
        return True
    # symbol table lookup: VAR or struct-field
    mv = re.match(rf"^({TOKEN})$", expr)
    if mv:
        info = symtab.get(mv.group(1).lower())
        if info and info.get("kind") in {"amount", "packed", "dec"}:
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
    # Mirror a finding at the declaration site of a simple variable
    if not re.match(r"^[A-Za-z_]\w*$", dest_token or ""):
        return
    decls = decl_index.get(dest_token.lower()) or []
    if not decls: return
    if too_small is None and SUPPRESS_UNKNOWN:
        return
    for d in decls:
        decl_unit = units[d.unit_idx]
        if too_small is True:
            msg = f"Declaration of '{dest_token}' appears too small for AFLE amount used in {usage_unit.inc_name}/{usage_unit.name} at line {usage_line}."
            sev = "error"; sug = f"Widen to AFLE-safe length (≥{MIN_DIGITS_FOR_AMOUNT}, e.g. P LENGTH 23 DECIMALS 2 or DDIC element)."
            itype = "DeclarationAFLESizeRisk"
        else:
            msg = f"Declaration of '{dest_token}' capacity unknown for AFLE amount usage at {usage_unit.inc_name}/{usage_unit.name} line {usage_line}."
            sev = "info"; sug = f"Verify declaration supports AFLE (≥{MIN_DIGITS_FOR_AMOUNT} digits)."
            itype = "DeclarationAFLECapacityUnknown"
        mirror = pack_decl_issue(
            decl_unit=decl_unit,
            decl_line=d.line,
            decl_text=d.text,
            issue_type=itype,
            message=msg,
            severity=sev,
            suggestion=sug,
            meta={}
        )
        mirror_buckets.setdefault(d.unit_idx, []).append(mirror)

def _select_list_has_amounts(select_list: str, symtab: Dict[str, Dict[str, Any]]) -> bool:
    if not select_list: return False
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

    # Concatenations / string ops with amount-like tokens
    for m in CONCATENATE_STMT.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, t) for t in re.findall(TOKEN, seg)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used in CONCATENATE; string ops ignore scale/precision.",
                                       "warning", m.start(), m.end(),
                                       "Avoid concatenating amounts; format only for UI."))
    for m in STRING_OP_AND.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, t) for t in re.findall(TOKEN, seg)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used with '&&' operator.",
                                       "warning", m.start(), m.end(),
                                       "Avoid string ops with amounts; use numeric ops + formatting."))
    for m in STRING_TEMPLATE.finditer(src):
        if any(is_amount_like(symtab, t) for t in re.findall(TOKEN, m.group(0))):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used inside string template.",
                                       "info", m.start(), m.end(),
                                       "Templates OK for UI; avoid persisting templated amounts."))

    # Offset/length access
    for m in OFFSET_LEN.finditer(src):
        var, off, ln = m.group(1), int(m.group(2)), int(m.group(3))
        if is_amount_like(symtab, var):
            findings.append(pack_issue(unit, "OffsetLengthAccess",
                                       f"Offset/length on amount {var}: +{off}({ln}).",
                                       "warning", m.start(), m.end(),
                                       "Do not slice amounts; use numeric ops or formatting."))

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
                               f"Use AFLE-safe type (≥{MIN_DIGITS_FOR_AMOUNT} digits), e.g. P LENGTH 23 DECIMALS 2 or appropriate DDIC element.")
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
                               f"Ensure destination is AFLE-safe (≥{MIN_DIGITS_FOR_AMOUNT} digits).")
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
            # literal on other side?
            is_lit = bool(re.match(r"^'.*'$", right)) or right.replace(".","",1).isdigit() \
                     or bool(re.match(r"^'.*'$", left))  or left.replace(".","",1).isdigit()
            other = right if left_is_amt else left
            if is_lit:
                findings.append(pack_issue(unit, "CompareLengthConflict",
                                           "Comparison between amount and literal.",
                                           "info", m.start(), m.end(),
                                           "Prefer numeric compares; ensure literal semantics are intended."))
                continue
            cshort = char_too_short(symtab, other)
            dshort = dec_too_short(symtab, other)
            too_small = (cshort is True) or (dshort is True)
            if too_small:
                usage = pack_issue(unit, "CompareLengthConflict",
                                   "Comparison with amount and short variable.",
                                   "error", m.start(), m.end(),
                                   f"Widen non-amount side to AFLE-safe (≥{MIN_DIGITS_FOR_AMOUNT} digits).")
                findings.append(usage)
                if re.match(r"^[A-Za-z_]\w*$", other or ""):
                    _emit_decl_mirrors(other, usage["issue_type"], usage["severity"], unit,
                                       usage["line"], decl_index, units, mirror_buckets, True)
            elif (cshort is None and dshort is None) and not SUPPRESS_UNKNOWN:
                findings.append(pack_issue(unit, "CompareLengthConflict",
                                           "Comparison with amount; other side capacity unknown.",
                                           "info", m.start(), m.end(),
                                           f"Verify the other side supports AFLE (≥{MIN_DIGITS_FOR_AMOUNT} digits)."))

    # SELECT ... INTO (only if select list has amount-like tokens)
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
                               f"Align destination to DB type (AFLE-compliant P/DEC; ≥{MIN_DIGITS_FOR_AMOUNT} digits).")
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, True)
        elif (cshort is None and dshort is None) and not SUPPRESS_UNKNOWN:
            findings.append(pack_issue(unit, "OpenSQLTypeConflict",
                                       f"SELECT list includes amounts; {dest} capacity unknown.",
                                       "info", m.start(), m.end(),
                                       f"Verify destination vs DB; use AFLE-compliant type (≥{MIN_DIGITS_FOR_AMOUNT} digits)."))

    # WRITE TO <char target>
    for m in WRITE_TO_STMT.finditer(src):
        target = m.group(2)
        cshort = char_too_short(symtab, target, min_len=MIN_CHAR_FOR_AMOUNT)
        if cshort is True:
            findings.append(pack_issue(unit, "WriteToTruncationRisk",
                                       f"WRITE TO target {target} may truncate formatted AFLE amounts.",
                                       "error", m.start(), m.end(),
                                       f"Increase target CHAR length (≥{MIN_CHAR_FOR_AMOUNT}) or format properly."))

    res = unit.model_dump()
    res["amount_findings"] = findings
    return res

# =========================
# Orchestrator
# =========================
def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    flat_src = "\n".join(u.code or "" for u in units)
    symtab = build_symbol_table(flat_src)
    decl_index = build_declaration_index(units)

    mirror_buckets: MirrorBucket = {}
    results = []
    for idx, u in enumerate(units):
        results.append(scan_unit(idx, u, symtab, decl_index, units, mirror_buckets))

    # inject mirrors
    for uidx, mirrors in mirror_buckets.items():
        if mirrors and uidx < len(results):
            results[uidx].setdefault("amount_findings", []).extend(mirrors)
    return results

# =========================
# API
# =========================
@app.post("/scan-amount")
def scan_amount(units: List[Unit]):
    t0 = time.perf_counter()
    out = analyze_units(units)
    _ = time.perf_counter() - t0  # elapsed (unused)
    return out

@app.get("/health")
def health():
    return {
        "ok": True,
        "now_utc": datetime.utcnow().isoformat() + "Z",
        "ddic_path": str(DDIC_PATH),
        "ddic_loaded": bool(DDIC.de or DDIC.tf),
        "counts": {"data_elements": len(DDIC.de), "table_fields": len(DDIC.tf)},
        "thresholds": {
            "MIN_DIGITS_FOR_AMOUNT": MIN_DIGITS_FOR_AMOUNT,
            "MIN_CHAR_FOR_AMOUNT": MIN_CHAR_FOR_AMOUNT,
            "SUPPRESS_UNKNOWN": SUPPRESS_UNKNOWN,
        }
    }
