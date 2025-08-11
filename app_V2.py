# app_amount_scan_odata_offline.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any, Tuple
import os, re, json
from functools import lru_cache

# --- HTTP client: requests or httpx (fallback) ---
_http_impl = None
try:
    import requests as _http_impl
except Exception:
    try:
        import httpx as _http_impl
    except Exception:
        _http_impl = None  # pure offline

# ---------- Config via environment (all optional now) ----------
SAP_BASE_URL   = os.getenv("SAP_BASE_URL")   # e.g. "https://my.sap.host:443"
SAP_USER       = os.getenv("SAP_USER")
SAP_PASSWD     = os.getenv("SAP_PASSWD")
SAP_DDIC_SRV   = os.getenv("SAP_DDIC_SERVICE_PATH", "/sap/opu/odata/sap/ZDDIC_META_SRV")
SAP_VERIFY_TLS = os.getenv("SAP_VERIFY_TLS", "true").lower() != "false"
OFFLINE_MODE   = os.getenv("AFLE_OFFLINE", "false").lower() == "true"

# Optional local DDIC catalog for offline enrichment
# JSON format:
# {
#   "data_elements": {"DMBTR":{"len":23,"dec":2,"domname":"..."}},
#   "table_fields": {"BSEG-DMBTR":{"len":23,"dec":2,"rollname":"DMBTR","domname":"..."}}
# }
CATALOG_PATH = os.getenv("AFLE_DDIC_CATALOG_JSON")
DDIC_CATALOG: Optional[Dict[str, Any]] = None
if CATALOG_PATH and os.path.exists(CATALOG_PATH):
    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            DDIC_CATALOG = json.load(f)
    except Exception:
        DDIC_CATALOG = None

# ---------- OData DDIC client with graceful offline ----------
class DDICClient:
    def __init__(self):
        self.base  = (SAP_BASE_URL or "").rstrip("/")
        self.path  = (SAP_DDIC_SRV or "").rstrip("/")
        self.user  = SAP_USER
        self.passw = SAP_PASSWD
        self.verify = SAP_VERIFY_TLS
        self.online_enabled = (
            not OFFLINE_MODE and
            _http_impl is not None and
            bool(self.base and self.user and self.passw and self.path)
        )
        # Precreate session if online_enabled
        self.session = None
        if self.online_enabled:
            try:
                if _http_impl.__name__ == "requests":
                    self.session = _http_impl.Session()
                    self.session.auth = (self.user, self.passw)
                    self.session.headers.update({"Accept": "application/json"})
                else:
                    # httpx
                    self.session = _http_impl.Client(auth=(self.user, self.passw), headers={"Accept":"application/json"}, verify=self.verify)
            except Exception:
                self.online_enabled = False
                self.session = None

    def _url(self, tail: str) -> str:
        return f"{self.base}{self.path}{tail}"

    @lru_cache(maxsize=2048)
    def get_data_element(self, name: str) -> Optional[Dict[str, Any]]:
        """Try local catalog -> online OData -> None."""
        if not name:
            return None
        # 1) local catalog
        if DDIC_CATALOG and "data_elements" in DDIC_CATALOG:
            hit = DDIC_CATALOG["data_elements"].get(name.upper())
            if hit:
                return {"len": hit.get("len"), "dec": hit.get("dec"), "domname": hit.get("domname"), "source": "catalog"}
        # 2) online OData
        if self.online_enabled and self.session is not None:
            try:
                url = self._url(f"/DataElement('{name.upper()}')")
                r = self.session.get(url, verify=self.verify) if _http_impl.__name__ == "requests" else self.session.get(url)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and "d" in data:
                        data = data["d"].get("results", data["d"])
                    return {
                        "len": int(data.get("LENG")) if data.get("LENG") not in (None, "") else None,
                        "dec": int(data.get("DECIMALS")) if data.get("DECIMALS") not in (None, "") else None,
                        "domname": data.get("DOMNAME"),
                        "source": "odata"
                    }
                # 404 -> None; other status -> treat as offline
            except Exception:
                pass
        # 3) offline
        return None

    @lru_cache(maxsize=4096)
    def get_table_field(self, tabname: str, fieldname: str) -> Optional[Dict[str, Any]]:
        """Try local catalog -> online OData -> None."""
        if not (tabname and fieldname):
            return None
        key = f"{tabname.upper()}-{fieldname.upper()}"
        # 1) local catalog
        if DDIC_CATALOG and "table_fields" in DDIC_CATALOG:
            hit = DDIC_CATALOG["table_fields"].get(key)
            if hit:
                return {
                    "len": hit.get("len"),
                    "dec": hit.get("dec"),
                    "rollname": hit.get("rollname"),
                    "domname": hit.get("domname"),
                    "source": "catalog"
                }
        # 2) online OData
        if self.online_enabled and self.session is not None:
            try:
                url = self._url(f"/TableField(Tabname='{tabname.upper()}',Fieldname='{fieldname.upper()}')")
                r = self.session.get(url, verify=self.verify) if _http_impl.__name__ == "requests" else self.session.get(url)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, dict) and "d" in data:
                        data = data["d"].get("results", data["d"])
                    return {
                        "len": int(data.get("LENG")) if data.get("LENG") not in (None, "") else None,
                        "dec": int(data.get("DECIMALS")) if data.get("DECIMALS") not in (None, "") else None,
                        "rollname": data.get("ROLLNAME"),
                        "domname": data.get("DOMNAME"),
                        "source": "odata"
                    }
            except Exception:
                pass
        # 3) offline
        return None

ddic = DDICClient()

# ---------- FastAPI ----------
app = FastAPI(title="Amount Field Scanner (AFLE) via OData DDIC (offline-capable)", version="1.1")

# ---------- Input model ----------
class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: str
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: str

# ---------- Regexes ----------
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

# ---------- Helpers ----------
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

# ---------- Local symbols + DDIC-aware lookup (offline-capable) ----------
DECL_SPLIT = re.compile(r"\.", re.DOTALL)

def build_symbol_table(full_src: str) -> Dict[str, Dict[str, Any]]:
    st: Dict[str, Dict[str, Any]] = {}
    for stmt in DECL_SPLIT.split(full_src):
        s = stmt.strip()
        if not s:
            continue
        # CHAR
        m = DECL_CHAR_LEN_PAREN.search(s)
        if m: st[m.group(2).lower()] = {"kind":"char","len":int(m.group(3))}
        m = DECL_CHAR_LEN_EXPL.search(s)
        if m: st[m.group(2).lower()] = {"kind":"char","len":int(m.group(3))}
        # P/DEC
        m = DECL_PACKED.search(s)
        if m:
            st[m.group(2).lower()] = {"kind":"packed","len":int(m.group(4)) if m.group(4) else None,
                                      "dec":int(m.group(6)) if m.group(6) else None}
        m = DECL_DEC_TYPE.search(s)
        if m:
            st[m.group(2).lower()] = {"kind":"dec","len":int(m.group(4)) if m.group(4) else None,
                                      "dec":int(m.group(6)) if m.group(6) else None}
        # TYPE <de> -> DDIC (via catalog/odata/none)
        m = DECL_TYPE_GENERIC.search(s)
        if m:
            var, de = m.group(2).lower(), m.group(3)
            info = ddic_lookup_token(de)
            if info:
                st[var] = {"kind": ("amount" if info["dec"] is not None else "char"),
                           "len": info["len"], "dec": info["dec"], "ddic": de}
    return st

def ddic_lookup_token(token: str) -> Optional[Dict[str, Any]]:
    t = token.strip().upper()
    # table-field?
    if "-" in t:
        parts = t.split("-")
        if len(parts) == 2:
            tf = ddic.get_table_field(parts[0], parts[1])
            if tf:
                kind = "amount" if tf.get("dec") is not None else "char"
                return {"len": tf.get("len"), "dec": tf.get("dec"), "kind": kind, "source": tf.get("source", "unknown")}
        return None
    # data element?
    de = ddic.get_data_element(t)
    if de:
        kind = "amount" if de.get("dec") is not None else "char"
        return {"len": de.get("len"), "dec": de.get("dec"), "kind": kind, "source": de.get("source", "unknown")}
    return None

def is_amount_like(symtab: Dict[str, Dict[str, Any]], expr: str) -> bool:
    expr = expr.strip()
    dd = ddic_lookup_token(expr)
    if dd and (dd["dec"] is not None or AMOUNT_NAME_HINT.search(expr)):
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
        return ln < min_len
    info = symtab.get(token.lower())
    if not info: return None
    if info["kind"] == "char":
        return (info.get("len") or 0) < min_len
    return False

def dec_too_short(symtab: Dict[str, Dict[str, Any]], token: str, min_digits: int = 23) -> Optional[bool]:
    dd = ddic_lookup_token(token)
    if dd and dd["kind"] in {"amount","dec","packed"}:
        ln = dd.get("len") or 0
        return ln and (ln < min_digits)
    info = symtab.get(token.lower())
    if not info: return None
    if info["kind"] in {"packed","dec","amount"}:
        ln = info.get("len") or 0
        return ln and (ln < min_digits)
    return False

# ---------- Scanner ----------
def scan_unit(unit: Unit, symtab: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    # 2) Concatenation
    for m in CONCATENATE_STMT.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, t.strip()) for t in re.split(r"[ ,]", seg)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used in CONCATENATE; string ops ignore scale/precision.",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Avoid amount concatenation; format for UI only."}))
    for m in STRING_OP_AND.finditer(src):
        seg = m.group(0)
        if any(is_amount_like(symtab, x.strip()) for x in re.split(r"&&", seg)):
            findings.append(pack_issue(unit, "ConcatenationDetected",
                                       "Amount used with '&&'.",
                                       "warning", m.start(), m.end(),
                                       {"suggestion":"Avoid string ops with amounts; use formatting."}))
    for m in STRING_TEMPLATE.finditer(src):
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

    # 4) Old move length conflict
    for m in MOVE_STMT.finditer(src):
        src_exp, dest = m.group(1).strip(), m.group(2)
        if is_amount_like(symtab, src_exp):
            cshort = char_too_short(symtab, dest)
            dshort = dec_too_short(symtab, dest)
            if cshort is True or dshort is True:
                findings.append(pack_issue(unit, "OldMoveLengthConflict",
                                           f"Moving amount into too-small destination {dest}.",
                                           "error", m.start(), m.end(),
                                           {"suggestion":"Use AFLE-safe type (DDIC amount or P LENGTH 23 DECIMALS 2)."}))
            elif cshort is None and dshort is None:
                findings.append(pack_issue(unit, "OldMoveLengthConflict",
                                           f"Move from amount into {dest} (destination type unknown).",
                                           "info", m.start(), m.end(),
                                           {"suggestion":"Verify {dest} capacity (≥23,2) or adjust DDIC element."}))
    for m in ASSIGNMENT.finditer(src):
        dest, src_exp = m.group(1), m.group(2)
        if is_amount_like(symtab, src_exp):
            cshort = char_too_short(symtab, dest)
            dshort = dec_too_short(symtab, dest)
            if cshort is True or dshort is True:
                findings.append(pack_issue(unit, "OldMoveLengthConflict",
                                           f"Assignment from amount into too-small {dest}.",
                                           "error", m.start(), m.end(),
                                           {"suggestion":"Widen {dest} to AFLE-safe amount type."}))
            elif cshort is None and dshort is None:
                findings.append(pack_issue(unit, "OldMoveLengthConflict",
                                           f"Assignment from amount into {dest} (type unknown).",
                                           "warning", m.start(), m.end(),
                                           {"suggestion":"Ensure {dest} supports AFLE; adjust DDIC or helper var."}))

    # 1) & 5) Compare length conflict
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
            sev = "warning" if is_lit else ("error" if (cshort is True or dshort is True) else "info")
            msg = "Comparison between amount and literal." if is_lit else \
                  ("Comparison with amount and short variable." if (cshort is True or dshort is True) else "Comparison with amount; verify other side length.")
            findings.append(pack_issue(unit, "CompareLengthConflict", msg, sev, m.start(), m.end(),
                                       {"suggestion":"Ensure both sides handle AFLE (widen short side / safe cast)."}))

    # Open SQL INTO
    for m in SELECT_INTO.finditer(src):
        dest = m.group(2)
        cshort = char_too_short(symtab, dest)
        dshort = dec_too_short(symtab, dest)
        if cshort is True or dshort is True:
            findings.append(pack_issue(unit, "OpenSQLTypeConflict",
                                       f"SELECT INTO {dest} may overflow/truncate AFLE amounts.",
                                       "error", m.start(), m.end(),
                                       {"suggestion":"Align {dest} to DB field type (AFLE-compliant).",
                                        "category":"Type conflicts in Open SQL"}))
        elif cshort is None and dshort is None:
            findings.append(pack_issue(unit, "OpenSQLTypeConflict",
                                       f"SELECT INTO {dest} with unknown destination capacity.",
                                       "info", m.start(), m.end(),
                                       {"suggestion":"Verify destination vs DB; use AFLE-compliant type.",
                                        "category":"Type conflicts in Open SQL"}))

    # LOOP/READ INTO
    loop_read = re.compile(r"\b(LOOP\s+AT|READ\s+TABLE)\b.+\bINTO\b\s+(\w+)", re.IGNORECASE)
    for m in loop_read.finditer(src):
        wa = m.group(2)
        cshort = char_too_short(symtab, wa)
        dshort = dec_too_short(symtab, wa)
        if cshort is True or dshort is True:
            findings.append(pack_issue(unit, "LoopReadTypeConflict",
                                       f"Work area {wa} may be too small for AFLE amounts in row.",
                                       "error", m.start(), m.end(),
                                       {"suggestion":"Adjust work area to AFLE-compliant lengths.",
                                        "category":"Type conflicts in LOOP/READ"}))

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

    # Floating-point / **
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
    # annotate scanner mode for transparency
    res["_scanner_mode"] = {
        "online_enabled": ddic.online_enabled,
        "http_client": None if _http_impl is None else _http_impl.__name__,
        "catalog_loaded": bool(DDIC_CATALOG is not None)
    }
    return res

def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    flat_src = "\n".join(u.code or "" for u in units)
    symtab = build_symbol_table(flat_src)
    return [scan_unit(u, symtab) for u in units]

# ---------- API ----------
app = FastAPI(title="Amount Field Scanner (AFLE) via OData DDIC — offline-capable", version="1.1")

@app.post("/scan-amount")
def scan_amount(units: List[Unit]):
    # No connectivity probe—always proceed
    return analyze_units(units)

@app.get("/health")
def health():
    return {
        "ok": True,
        "online_enabled": ddic.online_enabled,
        "http_client": None if _http_impl is None else _http_impl.__name__,
        "catalog_loaded": bool(DDIC_CATALOG is not None)
    }
