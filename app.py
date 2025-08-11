# app_amount_scan_webaware_decl_multiline.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os, re
from functools import lru_cache

# =========================
# Config (all optional)
# =========================
SAP_BASE_URL   = os.getenv("SAP_BASE_URL", "").rstrip("/")
SAP_USER       = os.getenv("SAP_USER", "")
SAP_PASSWD     = os.getenv("SAP_PASSWD", "")
SAP_DDIC_SRV   = os.getenv("SAP_DDIC_SERVICE_PATH", "/sap/opu/odata/sap/ZDDIC_META_SRV").rstrip("/")
SAP_VERIFY_TLS = os.getenv("SAP_VERIFY_TLS", "true").lower() != "false"

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
TAVILY_ENDPOINT = os.getenv("TAVILY_ENDPOINT", "https://api.tavily.com/search")

# HTTP client (requests → httpx → None)
_http = None
try:
    import requests as _http
except Exception:
    try:
        import httpx as _http
    except Exception:
        _http = None

app = FastAPI(
    title="Amount Field Scanner (AFLE) — SAP optional, Tavily web-aware, decl-site findings, multi-line decls",
    version="1.4"
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
# Regexes (AFLE scanning)
# =========================
DECL_CHAR_LEN_PAREN = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*\((\d+)\)\s*TYPE\s*C\b", re.IGNORECASE)
DECL_CHAR_LEN_EXPL  = re.compile(r"\b(DATA|CONSTANTS|FIELD-SYMBOLS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s*C\b[^.\n]*?\bLENGTH\b\s*(\d+)", re.IGNORECASE)
DECL_PACKED         = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+P\b[^.\n]*?(LENGTH\s+(\d+))?[^.\n]*?(DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_DEC_TYPE       = re.compile(r"\b(DATA|CONSTANTS|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+DEC\b[^.\n]*?(LENGTH\s+(\d+))?[^.\n]*?(DECIMALS\s+(\d+))?", re.IGNORECASE)
DECL_TYPE_GENERIC   = re.compile(r"\b(DATA|PARAMETERS|STATICS)\b[^.\n]*?\b(\w+)\b\s*TYPE\s+(\w+)\b", re.IGNORECASE)

ASSIGNMENT          = re.compile(r"\b(\w+)\s*=\s*([^\.\n]+)\.", re.IGNORECASE)
MOVE_STMT           = re.compile(r"\bMOVE\b\s+(.+?)\s+\bTO\b\s+(\w+)\s*\.", re.IGNORECASE)
SELECT_INTO         = re.compile(r"\bSELECT\b(.+?)\bINTO\b\s+@?(\w+)\b", re.IGNORECASE | re.DOTALL)
IF_BLOCK            = re.compile(r"\bIF\b\s+(.+?)\.\s*", re.IGNORECASE | re.DOTALL)
SIMPLE_CMP          = re.compile(r"(\w+)\s*(=|<>|NE|EQ|LT|LE|GT|GE)\s*('?[\w\.\-]+'?|\w+)", re.IGNORECASE)
CONCATENATE_STMT    = re.compile(r"\bCONCATENATE\b(.+?)\bINTO\b", re.IGNORECASE | re.DOTALL)
STRING_OP_AND       = re.compile(r"(.+?)\s*&&\s*(.+?)")
STRING_TEMPLATE     = re.compile(r"\|.*?\{[^}]*\}\|", re.DOTALL)
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

AMOUNT_NAME_HINT    = re.compile(r"(dmbtr|wrbtr|bapicurr|betrag|amount|amt|kbetr|netwr|mwskz)", re.IGNORECASE)

# For declaration indexing (line-by-line single-entry)
DECL_LINE_PATTERNS = [
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s*:\s*(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*(DATA|STATICS|CONSTANTS|PARAMETERS)\s+(\w+)\b.*\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*FIELD-SYMBOLS\s*<(\w+)>\b.*\.\s*$", re.IGNORECASE),
]

# --- New for multi-line colon-style declarations ---
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
    r"^\s*(?P<var>\w+)\s*(?:"
    r"TYPE\s+(?P<dtype>\w+)(?:\s+LENGTH\s+(?P<len>\d+))?(?:\s+DECIMALS\s+(?P<dec>\d+))?"
    r"|LIKE\s+(?P<like>\w+)"
    r"|\((?P<charlen>\d+)\)\s*TYPE\s*C"
    r")?",
    re.IGNORECASE
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
# Resolvers: SAP → Tavily → Regex
# =========================
class SAPOData:
    def __init__(self):
        self.enabled = bool(_http and SAP_BASE_URL and SAP_USER and SAP_PASSWD and SAP_DDIC_SRV)
        if self.enabled and _http.__name__ == "requests":
            self.session = _http.Session()
            self.session.auth = (SAP_USER, SAP_PASSWD)
            self.session.headers.update({"Accept": "application/json"})
        elif self.enabled and _http.__name__ == "httpx":
            self.session = _http.Client(auth=(SAP_USER, SAP_PASSWD), headers={"Accept":"application/json"}, verify=SAP_VERIFY_TLS)
        else:
            self.session = None
            self.enabled = False

    def _url(self, tail: str) -> str:
        return f"{SAP_BASE_URL}{SAP_DDIC_SRV}{tail}"

    @lru_cache(maxsize=1024)
    def data_element(self, name: str) -> Optional[Dict[str, Any]]:
        if not self.enabled or not name:
            return None
        try:
            url = self._url(f"/DataElement('{name.upper()}')")
            r = self.session.get(url, verify=SAP_VERIFY_TLS) if _http.__name__ == "requests" else self.session.get(url)
            if r.status_code != 200:
                return None
            data = r.json()
            if isinstance(data, dict) and "d" in data:
                data = data["d"].get("results", data["d"])
            return {
                "len": int(data.get("LENG")) if data.get("LENG") not in (None, "") else None,
                "dec": int(data.get("DECIMALS")) if data.get("DECIMALS") not in (None, "") else None,
                "domname": data.get("DOMNAME"),
                "source": "sap_odata"
            }
        except Exception:
            return None

    @lru_cache(maxsize=2048)
    def table_field(self, tab: str, field: str) -> Optional[Dict[str, Any]]:
        if not self.enabled or not (tab and field):
            return None
        try:
            url = self._url(f"/TableField(Tabname='{tab.upper()}',Fieldname='{field.upper()}')")
            r = self.session.get(url, verify=SAP_VERIFY_TLS) if _http.__name__ == "requests" else self.session.get(url)
            if r.status_code != 200:
                return None
            data = r.json()
            if isinstance(data, dict) and "d" in data:
                data = data["d"].get("results", data["d"])
            return {
                "len": int(data.get("LENG")) if data.get("LENG") not in (None, "") else None,
                "dec": int(data.get("DECIMALS")) if data.get("DECIMALS") not in (None, "") else None,
                "rollname": data.get("ROLLNAME"),
                "domname": data.get("DOMNAME"),
                "source": "sap_odata"
            }
        except Exception:
            return None

class TavilyResolver:
    def __init__(self):
        self.enabled = bool(_http and TAVILY_API_KEY)

    def _search(self, query: str) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []
        try:
            payload = {
                "api_key": TAVILY_API_KEY,
                "query": query,
                "include_answer": False,
                "include_images": False,
                "max_results": 5
            }
            resp = _http.post(TAVILY_ENDPOINT, json=payload, timeout=20)
            if resp.status_code != 200:
                return []
            data = resp.json()
            return data.get("results", [])
        except Exception:
            return []

    @staticmethod
    def _parse_lengths(text: str) -> Dict[str, Optional[int]]:
        text = text or ""
        m = re.search(r"(\d{2})\s+digits?\s+including\s+(\d)\s+decimals?", text, re.IGNORECASE)
        if m:
            return {"len": int(m.group(1)), "dec": int(m.group(2))}
        m = re.search(r"length\s*[:=]\s*(\d+)", text, re.IGNORECASE)
        n = re.search(r"decimals?\s*[:=]\s*(\d+)", text, re.IGNORECASE)
        return {"len": int(m.group(1)) if m else None, "dec": int(n.group(1)) if n else None}

    def data_element(self, name: str) -> Optional[Dict[str, Any]]:
        if not self.enabled or not name:
            return None
        q = f"SAP data element {name} length decimals"
        for r in self._search(q):
            meta = self._parse_lengths((r.get("snippet") or "") + " " + (r.get("content") or ""))
            if meta["len"] or meta["dec"] is not None:
                meta["source"] = "tavily"
                return meta
        return None

    def table_field(self, tab: str, field: str) -> Optional[Dict[str, Any]]:
        if not self.enabled or not (tab and field):
            return None
        q = f"SAP table {tab} field {field} length decimals"
        for r in self._search(q):
            meta = self._parse_lengths((r.get("snippet") or "") + " " + (r.get("content") or ""))
            if meta["len"] or meta["dec"] is not None:
                meta["source"] = "tavily"
                return meta
        return None

sap = SAPOData()
tav = TavilyResolver()

# =========================
# Symbol table & lookups
# =========================
DECL_SPLIT = re.compile(r"\.", re.DOTALL)

def ddic_lookup_token(token: str) -> Optional[Dict[str, Any]]:
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

def build_symbol_table(full_src: str) -> Dict[str, Dict[str, Any]]:
    st: Dict[str, Dict[str, Any]] = {}
    for stmt, _, _ in iter_statements_with_offsets(full_src):
        s = stmt.strip()
        if not s:
            continue
        # existing single-line patterns
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

        # NEW: multi-line colon header
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
    """
    var_name_lower -> [DeclSite, ...]
    Uses statement iteration to capture single-line and multi-line colon blocks with line numbers.
    """
    index: Dict[str, List[DeclSite]] = {}
    for uidx, u in enumerate(units):
        src = u.code or ""
        for stmt, s_off, e_off in iter_statements_with_offsets(src):
            stripped = stmt.strip()

            # single-line patterns
            matched_single = False
            for pat in DECL_LINE_PATTERNS:
                m = pat.match(stripped)
                if m:
                    if pat.pattern.startswith(r"^\s*FIELD-SYMBOLS"):
                        var = (m.group(1) or "").lower()
                    else:
                        var = (m.group(2) or "").lower()
                    if var:
                        index.setdefault(var, []).append(DeclSite(var, uidx, line_of_offset(src, s_off), stripped))
                        matched_single = True
                    break
            # continue to check multi-line too (same statement can satisfy both)

            # multi-line colon block
            mcol = DECL_HEADER_COLON.match(stripped)
            if not mcol:
                continue
            body = mcol.group(2)
            if body.endswith("."):
                body = body[:-1]
            entries = smart_split_commas(body)
            rel = 0
            # compute offset where 'body' starts within 'stmt'
            body_rel_off = stripped.find(body)
            stmt_abs_start = s_off + (len(stmt) - len(stripped))  # adjust for leading spaces trimmed by strip
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

def char_too_short(symtab: Dict[str, Dict[str, Any]], token: str, min_len: int = 25) -> Optional[bool]:
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

def dec_too_short(symtab: Dict[str, Dict[str, Any]], token: str, min_digits: int = 23) -> Optional[bool]:
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

# =========================
# Scanner (with decl-site mirrors)
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
    for d in decls:
        decl_unit = units[d.unit_idx]
        if too_small is True:
            msg = f"Declaration of '{dest_token}' appears too small for AFLE amounts used in {usage_unit.inc_name}/{usage_unit.name} at line {usage_line}."
            sev = usage_severity  # typically 'error'
            sug = "Widen the declared type to an AFLE-safe amount (e.g., DDIC amount or P LENGTH 23 DECIMALS 2)."
            itype = "DeclarationAFLESizeRisk"
        else:
            msg = f"Declaration of '{dest_token}' may be insufficient for AFLE amounts used in {usage_unit.inc_name}/{usage_unit.name} at line {usage_line} (destination capacity unknown)."
            sev = "info" if usage_severity == "info" else "warning"
            sug = "Verify the declared type supports AFLE (≥23,2) or adjust DDIC element."
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

def scan_unit(unit_idx: int,
              unit: Unit,
              symtab: Dict[str, Dict[str, Any]],
              decl_index: Dict[str, List[DeclSite]],
              units: List[Unit],
              mirror_buckets: MirrorBucket) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    # 2) Concatenation
    for m in CONCATENATE_STMT.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, t.strip()) for t in re.split(r"[ ,]", seg)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used in CONCATENATE; string ops ignore scale/precision.",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Avoid amount concatenation; format only for UI."}))
    for m in STRING_OP_AND.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, x.strip()) for x in re.split(r"&&", seg)):
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

    # 4) Old move length conflict (MOVE ...)
    for m in MOVE_STMT.finditer(src):
        src_exp, dest = m.group(1).strip(), m.group(2)
        if is_amount_like(symtab, src_exp):
            cshort = char_too_short(symtab, dest)
            dshort = dec_too_short(symtab, dest)
            too_small = (cshort is True) or (dshort is True)
            sev = "error" if too_small else "info"
            usage = pack_issue(unit, "OldMoveLengthConflict",
                               f"Moving amount into {dest} " + ("(too small)." if too_small else "(destination capacity unknown)."),
                               sev, m.start(), m.end(),
                               {"suggestion":"Use AFLE-safe type (e.g., DDIC amount or P LENGTH 23 DECIMALS 2)."})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, too_small)

    # 4) Old move length conflict (assignment =)
    for m in ASSIGNMENT.finditer(src):
        dest, src_exp = m.group(1), m.group(2)
        if is_amount_like(symtab, src_exp):
            cshort = char_too_short(symtab, dest)
            dshort = dec_too_short(symtab, dest)
            too_small = (cshort is True) or (dshort is True)
            sev = "error" if too_small else "warning"
            usage = pack_issue(unit, "OldMoveLengthConflict",
                               f"Assignment from amount into {dest} " + ("(too small)." if too_small else "(type unknown)."),
                               sev, m.start(), m.end(),
                               {"suggestion":"Ensure destination is AFLE-safe (≥23,2) or adjust DDIC element."})
            findings.append(usage)
            _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                               usage["line"], decl_index, units, mirror_buckets, too_small)

    # 1) & 5) Compare length conflicts
    for m in IF_BLOCK.finditer(src):
        cond = m.group(1)
        for c in SIMPLE_CMP.finditer(cond):
            left, op, right = c.group(1), c.group(2), c.group(3)
            left_is_amt  = is_amount_like(symtab, left)
            right_is_amt = is_amount_like(symtab, right)
            if not (left_is_amt or right_is_amt):
                continue
            is_lit = bool(re.match(r"^'.*'$", right)) or right.replace(".","",1).isdigit() \
                     or bool(re.match(r"^'.*'$", left))  or left.replace(".","",1).isdigit()
            other = right if left_is_amt else left
            cshort = char_too_short(symtab, other) if not is_lit else None
            dshort = dec_too_short(symtab, other) if not is_lit else None
            too_small = (cshort is True) or (dshort is True)
            sev = "warning" if is_lit else ("error" if too_small else "info")
            msg = "Comparison between amount and literal." if is_lit else \
                  ("Comparison with amount and short variable." if too_small else "Comparison with amount; verify other side length.")
            usage = pack_issue(unit, "CompareLengthConflict", msg, sev, m.start(), m.end(),
                               {"suggestion":"Ensure both sides support AFLE (widen short side / safe cast)."})
            findings.append(usage)
            if not is_lit and re.match(r"^[A-Za-z_]\w*$", other or ""):
                _emit_decl_mirrors(other, usage["issue_type"], usage["severity"], unit,
                                   usage["line"], decl_index, units, mirror_buckets, too_small)

    # Open SQL INTO
    for m in SELECT_INTO.finditer(src):
        dest = m.group(2)
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        too_small = (cshort is True) or (dshort is True)
        if too_small:
            usage = pack_issue(unit, "OpenSQLTypeConflict",
                               f"SELECT INTO {dest} may overflow/truncate AFLE amounts.",
                               "error", m.start(), m.end(),
                               {"suggestion":"Align {dest} to DB field type (AFLE-compliant).",
                                "category":"Type conflicts in Open SQL"})
        else:
            usage = pack_issue(unit, "OpenSQLTypeConflict",
                               f"SELECT INTO {dest} with unknown destination capacity.",
                               "info", m.start(), m.end(),
                               {"suggestion":"Verify destination vs DB; use AFLE-compliant type.",
                                "category":"Type conflicts in Open SQL"})
        findings.append(usage)
        _emit_decl_mirrors(dest, usage["issue_type"], usage["severity"], unit,
                           usage["line"], decl_index, units, mirror_buckets, too_small)

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
                               usage["line"], decl_index, units, mirror_buckets, too_small)

    # MOVE-CORRESPONDING
    for m in MOVE_CORRESP.finditer(src):
        findings.append(pack_issue(unit, "MoveCorrespondingRisk",
                                   "MOVE-CORRESPONDING may map extended amount to short field.",
                                   "warning", m.start(), m.end(),
                                   {"suggestion":"Align structures or use CORRESPONDING #( ... MAPPING ... )."}))

    # WRITE / WRITE TO
    for m in WRITE_STMT.finditer(src):
        findings.append(pack_issue(unit, "ListWriteLayoutRisk",
                                   "WRITE list output may misalign due to AFLE output length.",
                                   "info", m.start(), m.end(),
                                   {"suggestion":"Specify explicit (len) or shift columns for classic lists.",
                                    "category":"WRITE statements (list output)"}))
    for m in WRITE_TO_STMT.finditer(src):
        target = m.group(2)
        cshort = char_too_short(symtab, target, min_len=25)
        if cshort is True:
            findings.append(pack_issue(unit, "WriteToTruncationRisk",
                                       f"WRITE TO target {target} may truncate AFLE amounts.",
                                       "error", m.start(), m.end(),
                                       {"suggestion":"Increase target CHAR length (≥25) or format properly.",
                                        "category":"WRITE TO"}))

    # Floating point / exponentiation
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
        "sap_online": sap.enabled,
        "tavily_online": tav.enabled,
        "http_client": None if _http is None else _http.__name__
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
    mirror_buckets: MirrorBucket = {}
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
def scan_amount(units: List[Unit]):
    return analyze_units(units)

@app.get("/health")
def health():
    return {
        "ok": True,
        "sap_online": sap.enabled,
        "tavily_online": tav.enabled,
        "http_client": None if _http is None else _http.__name__
    }

# To run:
# pip install fastapi uvicorn requests  # or httpx
# export TAVILY_API_KEY="your_tavily_key"  # optional, but recommended
# uvicorn app_amount_scan_webaware_decl_multiline:app --host 0.0.0.0 --port 8046
