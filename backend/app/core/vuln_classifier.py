"""
Vulnerability Classification System
CWE/CAPEC/OWASP mapping for standardized vulnerability categorization.
Aligns with industry standards for compliance and reporting.
"""
from enum import Enum
from typing import Dict, List, Optional


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTO_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIG = "A05:2021 - Security Misconfiguration"
    A06_VULN_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_MONITORING = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"


CWE_MAP: Dict[str, dict] = {
    "sqli": {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-66"],
    },
    "xss": {
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-63", "CAPEC-591"],
    },
    "ssrf": {
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "owasp": OWASPCategory.A10_SSRF,
        "capec_ids": ["CAPEC-664"],
    },
    "rce": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-88"],
    },
    "file-upload": {
        "cwe_id": "CWE-434",
        "cwe_name": "Unrestricted Upload of File with Dangerous Type",
        "owasp": OWASPCategory.A04_INSECURE_DESIGN,
        "capec_ids": ["CAPEC-650"],
    },
    "lfi": {
        "cwe_id": "CWE-98",
        "cwe_name": "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-175", "CAPEC-252"],
    },
    "ssti": {
        "cwe_id": "CWE-1336",
        "cwe_name": "Improper Neutralization of Special Elements Used in a Template Engine",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "xxe": {
        "cwe_id": "CWE-611",
        "cwe_name": "Improper Restriction of XML External Entity Reference",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIG,
        "capec_ids": ["CAPEC-221"],
    },
    "csrf": {
        "cwe_id": "CWE-352",
        "cwe_name": "Cross-Site Request Forgery (CSRF)",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "capec_ids": ["CAPEC-62"],
    },
    "deserialization": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
        "capec_ids": ["CAPEC-586"],
    },
    "auth-bypass": {
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114", "CAPEC-115"],
    },
    "info-disclosure": {
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "capec_ids": ["CAPEC-116", "CAPEC-169"],
    },
    "path-traversal": {
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "capec_ids": ["CAPEC-126"],
    },
    "jndi": {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "spring": {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "shiro": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
        "capec_ids": ["CAPEC-586"],
    },
    "log4j2": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": OWASPCategory.A06_VULN_COMPONENTS,
        "capec_ids": ["CAPEC-242"],
    },
    "fastjson": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": OWASPCategory.A06_VULN_COMPONENTS,
        "capec_ids": ["CAPEC-586"],
    },
    "nacos": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "druid": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "tomcat": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "struts2": {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "thinkphp": {
        "cwe_id": "CWE-913",
        "cwe_name": "Improper Control of Dynamically-Managed Code Resources",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "weblogic": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "owasp": OWASPCategory.A06_VULN_COMPONENTS,
        "capec_ids": ["CAPEC-586"],
    },
    "redis": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "confluence": {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "f5": {
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-88"],
    },
    "jenkins": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "flink": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "xxljob": {
        "cwe_id": "CWE-917",
        "cwe_name": "Improper Neutralization of Special Elements used in an Expression Language Statement",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": ["CAPEC-242"],
    },
    "nginx": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIG,
        "capec_ids": ["CAPEC-114"],
    },
    "elasticsearch": {
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "capec_ids": ["CAPEC-114"],
    },
    "poc": {
        "cwe_id": "CWE-937",
        "cwe_name": "OWASP Top 10 2017 Category A1 - Injection",
        "owasp": OWASPCategory.A03_INJECTION,
        "capec_ids": [],
    },
    "general": {
        "cwe_id": "CWE-937",
        "cwe_name": "OWASP Top 10 2017 Category A1 - Injection",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIG,
        "capec_ids": [],
    },
}


RISK_LEVEL_CVSS_RANGE: Dict[str, tuple] = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "info": (0.0, 0.0),
}


def get_cwe_info(category: str) -> dict:
    return CWE_MAP.get(category, CWE_MAP["general"])


def get_owasp_category(category: str) -> OWASPCategory:
    info = CWE_MAP.get(category, CWE_MAP["general"])
    return info["owasp"]


def get_capec_ids(category: str) -> List[str]:
    info = CWE_MAP.get(category, CWE_MAP["general"])
    return info.get("capec_ids", [])


def get_cvss_range_for_risk(risk_level: str) -> tuple:
    return RISK_LEVEL_CVSS_RANGE.get(risk_level.lower(), (0.0, 0.0))


def classify_vulnerability(category: str, risk_level: str, cvss_score: float = 0.0) -> dict:
    cwe_info = get_cwe_info(category)
    return {
        "cwe_id": cwe_info["cwe_id"],
        "cwe_name": cwe_info["cwe_name"],
        "owasp_category": cwe_info["owasp"].value,
        "capec_ids": cwe_info["capec_ids"],
        "risk_level": risk_level,
        "cvss_score": cvss_score,
        "cvss_range": get_cvss_range_for_risk(risk_level),
    }


def get_all_categories() -> List[str]:
    return sorted(CWE_MAP.keys())


def get_owasp_summary() -> Dict[str, List[str]]:
    summary: Dict[str, List[str]] = {}
    for category, info in CWE_MAP.items():
        owasp = info["owasp"].value
        if owasp not in summary:
            summary[owasp] = []
        summary[owasp].append(category)
    return summary
