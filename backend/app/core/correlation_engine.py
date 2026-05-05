"""
漏洞关联分析引擎 - 多漏洞组合利用链检测

自动分析扫描结果中多个漏洞之间的关联关系，识别潜在的攻击链（Attack Chain）。
参考 ATT&CK 框架和 OWASP 组合漏洞利用模式，实现智能关联分析。

支持的攻击链类型：
- LFI + 文件上传 → RCE
- SQL注入 + 后台管理 → 数据泄露
- SSRF + 内网服务 → 内网渗透
- XSS + CSRF → 账户接管
- 信息泄露 + 弱口令 → 权限提升
- 反序列化 + 文件写入 → RCE
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urlparse

from app.utils.logger import get_logger

logger = get_logger(__name__)


class ChainSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ChainCategory(str, Enum):
    RCE_CHAIN = "rce_chain"
    DATA_BREACH = "data_breach"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    ACCOUNT_TAKEOVER = "account_takeover"
    INFO_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"


@dataclass
class ChainNode:
    vuln_id: str
    vuln_name: str
    category: str
    risk_level: str
    target_url: str
    role: str


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    category: ChainCategory
    severity: ChainSeverity
    nodes: List[ChainNode] = field(default_factory=list)
    exploit_path: List[str] = field(default_factory=list)
    impact_summary: str = ""
    mitigation_priority: str = ""
    confidence: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)
    attck_techniques: List[str] = field(default_factory=list)


@dataclass
class CorrelationReport:
    task_id: str
    total_vulns: int
    chains_found: int
    attack_chains: List[AttackChain] = field(default_factory=list)
    isolated_vulns: List[str] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


CHAIN_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "lfi-to-rce",
        "name": "LFI + 文件上传 → 远程代码执行",
        "description": "攻击者先利用文件包含漏洞读取源码，再结合文件上传漏洞写入WebShell，最终实现远程代码执行。这是最常见的组合利用链之一。",
        "category": ChainCategory.RCE_CHAIN,
        "severity": ChainSeverity.CRITICAL,
        "required_categories": ["lfi", "file-upload", "file-inclusion"],
        "min_nodes": 2,
        "exploit_path": [
            "1. 利用LFI漏洞读取应用源码和配置文件",
            "2. 通过文件上传漏洞上传恶意文件（WebShell）",
            "3. 利用LFI包含上传的恶意文件",
            "4. 获得远程代码执行权限",
        ],
        "impact_summary": "攻击者可获取服务器完全控制权，执行任意命令，窃取敏感数据。",
        "mitigation_priority": "立即修复文件上传和文件包含漏洞，配置文件上传白名单和路径限制。",
        "cwe_ids": ["CWE-98", "CWE-434"],
        "attck_techniques": ["T1190", "T1505"],
    },
    {
        "id": "sqli-to-data-breach",
        "name": "SQL注入 + 后台管理暴露 → 数据大规模泄露",
        "description": "SQL注入漏洞允许攻击者提取数据库内容，结合暴露的后台管理入口，可获取管理员凭证并批量导出敏感数据。",
        "category": ChainCategory.DATA_BREACH,
        "severity": ChainSeverity.CRITICAL,
        "required_categories": ["sql-injection", "sqli"],
        "optional_categories": ["admin-exposure", "backup-file", "info-leak"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 利用SQL注入获取数据库表结构和管理员密码哈希",
            "2. 破解或利用密码哈希登录后台管理",
            "3. 批量导出用户数据和业务敏感信息",
        ],
        "impact_summary": "可能导致全部用户数据泄露，违反数据安全法规，面临巨额罚款。",
        "mitigation_priority": "立即修复SQL注入漏洞，使用参数化查询，限制数据库账户权限。",
        "cwe_ids": ["CWE-89"],
        "attck_techniques": ["T1190", "T1213"],
    },
    {
        "id": "ssrf-to-internal-pivot",
        "name": "SSRF + 内网服务探测 → 内网横向移动",
        "description": "SSRF漏洞允许攻击者从外网探测和访问内网服务，结合发现的内部API或管理接口，可深入内网进行横向渗透。",
        "category": ChainCategory.LATERAL_MOVEMENT,
        "severity": ChainSeverity.HIGH,
        "required_categories": ["ssrf"],
        "optional_categories": ["info-leak", "unauthorized-access", "idor"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 利用SSRF探测内网存活主机和服务",
            "2. 发现内网管理接口或云元数据服务",
            "3. 利用内网服务漏洞进一步渗透",
            "4. 获取内网敏感信息或控制权限",
        ],
        "impact_summary": "攻击者可突破网络边界，访问内部系统，可能导致整个内网沦陷。",
        "mitigation_priority": "严格限制SSRF目标地址白名单，禁用不必要的URL scheme，网络隔离。",
        "cwe_ids": ["CWE-918"],
        "attck_techniques": ["T1190", "T1210", "T1552"],
    },
    {
        "id": "xss-to-account-takeover",
        "name": "XSS + CSRF → 账户接管",
        "description": "存储型XSS可窃取用户Cookie和Session，结合CSRF漏洞可构造自动化攻击链，实现批量账户接管。",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": ChainSeverity.HIGH,
        "required_categories": ["xss"],
        "optional_categories": ["csrf", "session-fixation", "weak-crypto"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 注入存储型XSS Payload窃取管理员Session",
            "2. 利用窃取的Session冒充管理员",
            "3. 结合CSRF漏洞批量修改用户密码或权限",
            "4. 完全控制应用和用户账户",
        ],
        "impact_summary": "攻击者可批量接管用户账户，包括管理员账户，完全控制应用。",
        "mitigation_priority": "实施CSP策略，HttpOnly Cookie，CSRF Token，输入输出编码。",
        "cwe_ids": ["CWE-79", "CWE-352"],
        "attck_techniques": ["T1189", "T1539"],
    },
    {
        "id": "info-leak-to-privilege-escalation",
        "name": "信息泄露 + 弱口令/默认凭证 → 权限提升",
        "description": "信息泄露漏洞暴露了系统配置、源码或账户信息，结合弱口令或默认凭证可直接获取高权限访问。",
        "category": ChainCategory.PRIVILEGE_ESCALATION,
        "severity": ChainSeverity.HIGH,
        "required_categories": ["info-leak", "info-leakage", "backup-file", "source-code-disclosure"],
        "optional_categories": ["weak-password", "default-credentials", "brute-force"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 通过信息泄露获取配置文件、数据库连接信息",
            "2. 发现硬编码的密码或API密钥",
            "3. 利用泄露的凭证访问高权限接口",
            "4. 提升权限至管理员级别",
        ],
        "impact_summary": "攻击者可从低权限提升至管理员，获取系统完全控制权。",
        "mitigation_priority": "移除源码中的硬编码凭证，限制敏感文件访问，实施最小权限原则。",
        "cwe_ids": ["CWE-200", "CWE-798"],
        "attck_techniques": ["T1552", "T1078"],
    },
    {
        "id": "deserialization-to-rce",
        "name": "反序列化 + 文件写入 → 远程代码执行",
        "description": "不安全的反序列化可触发任意对象实例化，结合文件写入能力可构造反序列化Gadget Chain实现RCE。",
        "category": ChainCategory.RCE_CHAIN,
        "severity": ChainSeverity.CRITICAL,
        "required_categories": ["deserialization", "insecure-deserialization"],
        "optional_categories": ["file-write", "file-upload", "rce"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 识别应用使用的序列化框架和版本",
            "2. 构造反序列化Gadget Chain",
            "3. 通过文件写入或参数注入触发反序列化",
            "4. 执行任意命令获取服务器控制权",
        ],
        "impact_summary": "可直接获取服务器远程代码执行权限，风险极高。",
        "mitigation_priority": "避免反序列化不可信数据，实施类型白名单检查，升级框架版本。",
        "cwe_ids": ["CWE-502"],
        "attck_techniques": ["T1190", "T1059"],
    },
    {
        "id": "idor-to-data-breach",
        "name": "IDOR + API未授权访问 → 越权数据泄露",
        "description": "不安全的直接对象引用（IDOR）允许攻击者遍历资源ID，结合未授权的API接口可批量获取其他用户数据。",
        "category": ChainCategory.DATA_BREACH,
        "severity": ChainSeverity.HIGH,
        "required_categories": ["idor", "unauthorized-access", "auth-bypass"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 发现API接口中存在可遍历的资源ID参数",
            "2. 批量遍历获取其他用户的敏感数据",
            "3. 结合未授权接口获取更高级别数据",
            "4. 大规模数据泄露",
        ],
        "impact_summary": "可批量获取所有用户数据，造成严重数据泄露事件。",
        "mitigation_priority": "实施严格的权限校验，使用随机UUID替代自增ID，记录审计日志。",
        "cwe_ids": ["CWE-639", "CWE-862"],
        "attck_techniques": ["T1213", "T1530"],
    },
    {
        "id": "rce-to-full-compromise",
        "name": "RCE + 弱权限配置 → 完全系统控制",
        "description": "远程代码执行漏洞本身已极高危，若服务器存在弱权限配置（如root运行），攻击者可立即获取系统完全控制权。",
        "category": ChainCategory.RCE_CHAIN,
        "severity": ChainSeverity.CRITICAL,
        "required_categories": ["rce", "command-injection", "code-injection"],
        "optional_categories": ["privilege-escalation", "misconfiguration"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 利用RCE漏洞执行系统命令",
            "2. 发现应用以高权限用户运行",
            "3. 植入持久化后门",
            "4. 横向移动攻击其他内网系统",
        ],
        "impact_summary": "服务器完全沦陷，可被用于挖矿、DDoS攻击、数据窃取等。",
        "mitigation_priority": "立即修复RCE漏洞，以最小权限运行应用，实施容器化隔离。",
        "cwe_ids": ["CWE-78", "CWE-94"],
        "attck_techniques": ["T1059", "T1505", "T1210"],
    },
    {
        "id": "open-redirect-to-phishing",
        "name": "开放重定向 + XSS → 钓鱼攻击链",
        "description": "开放重定向可伪装合法域名进行钓鱼，结合XSS可窃取用户在合法站点上的凭证。",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": ChainSeverity.MEDIUM,
        "required_categories": ["open-redirect", "url-redirect"],
        "optional_categories": ["xss", "phishing"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 构造看似合法的重定向URL",
            "2. 诱导用户点击跳转到钓鱼页面",
            "3. 结合XSS在返回原站时窃取凭证",
            "4. 获取用户账户控制权",
        ],
        "impact_summary": "可对用户实施精准钓鱼攻击，窃取账户凭证。",
        "mitigation_priority": "使用白名单验证重定向URL，实施Referer检查，用户安全意识培训。",
        "cwe_ids": ["CWE-601"],
        "attck_techniques": ["T1566", "T1204"],
    },
    {
        "id": "cors-to-data-theft",
        "name": "CORS配置错误 + 敏感API → 跨域数据窃取",
        "description": "CORS配置过于宽松允许任意域访问，结合返回敏感数据的API接口，可被恶意网站跨域窃取数据。",
        "category": ChainCategory.DATA_BREACH,
        "severity": ChainSeverity.HIGH,
        "required_categories": ["cors-misconfig", "cors"],
        "optional_categories": ["sensitive-data-exposure", "api-leak"],
        "min_nodes": 1,
        "exploit_path": [
            "1. 发现CORS配置允许任意Origin",
            "2. 识别返回敏感数据的API接口",
            "3. 构造恶意网页跨域请求API",
            "4. 窃取用户敏感数据",
        ],
        "impact_summary": "用户浏览恶意网页时，敏感数据可被静默窃取。",
        "mitigation_priority": "严格限制Access-Control-Allow-Origin为可信域名，敏感API禁用CORS。",
        "cwe_ids": ["CWE-942"],
        "attck_techniques": ["T1213", "T1189"],
    },
]


def _normalize_category(category: str) -> str:
    return category.lower().replace("_", "-").replace(" ", "-").strip()


def _url_same_host(url1: str, url2: str) -> bool:
    try:
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return p1.hostname == p2.hostname and p1.port == p2.port
    except Exception:
        return False


def _check_chain_match(
    pattern: Dict[str, Any],
    vulns: List[Dict[str, Any]],
) -> Optional[AttackChain]:
    required = [c.lower() for c in pattern.get("required_categories", [])]
    optional = [c.lower() for c in pattern.get("optional_categories", [])]

    matched_required: List[Dict[str, Any]] = []
    matched_optional: List[Dict[str, Any]] = []

    for vuln in vulns:
        vcat = _normalize_category(vuln.get("category", ""))
        if vcat in required:
            matched_required.append(vuln)
        elif vcat in optional:
            matched_optional.append(vuln)

    if len(matched_required) < pattern.get("min_nodes", 1):
        return None

    all_matched = matched_required + matched_optional

    if len(all_matched) < pattern.get("min_nodes", 1):
        return None

    nodes = []
    for i, vuln in enumerate(all_matched):
        role = "核心节点" if vuln in matched_required else "辅助节点"
        nodes.append(ChainNode(
            vuln_id=vuln.get("vuln_id", ""),
            vuln_name=vuln.get("name", ""),
            category=vuln.get("category", ""),
            risk_level=vuln.get("risk_level", "medium"),
            target_url=vuln.get("target_url", ""),
            role=role,
        ))

    confidence = min(0.95, 0.5 + 0.15 * len(matched_required) + 0.05 * len(matched_optional))

    return AttackChain(
        chain_id=pattern["id"],
        name=pattern["name"],
        description=pattern["description"],
        category=pattern["category"],
        severity=pattern["severity"],
        nodes=nodes,
        exploit_path=pattern.get("exploit_path", []),
        impact_summary=pattern.get("impact_summary", ""),
        mitigation_priority=pattern.get("mitigation_priority", ""),
        confidence=round(confidence, 2),
        cwe_ids=pattern.get("cwe_ids", []),
        attck_techniques=pattern.get("attck_techniques", []),
    )


def analyze_correlations(
    task_id: str,
    vulnerabilities: List[Dict[str, Any]],
) -> CorrelationReport:
    """
    分析漏洞之间的关联关系，识别攻击链。

    Args:
        task_id: 扫描任务ID
        vulnerabilities: 漏洞列表，每个漏洞需包含 vuln_id, name, category, risk_level, target_url

    Returns:
        CorrelationReport 包含所有发现的攻击链
    """
    if not vulnerabilities:
        return CorrelationReport(
            task_id=task_id,
            total_vulns=0,
            chains_found=0,
        )

    vulns = []
    for v in vulnerabilities:
        vulns.append({
            "vuln_id": v.get("vuln_id", ""),
            "name": v.get("name", ""),
            "category": v.get("category", ""),
            "risk_level": v.get("risk_level", "medium"),
            "target_url": v.get("target_url", ""),
        })

    chains: List[AttackChain] = []
    for pattern in CHAIN_PATTERNS:
        chain = _check_chain_match(pattern, vulns)
        if chain:
            chains.append(chain)

    chains.sort(key=lambda c: (
        0 if c.severity == ChainSeverity.CRITICAL else
        1 if c.severity == ChainSeverity.HIGH else
        2 if c.severity == ChainSeverity.MEDIUM else 3,
        -c.confidence,
    ))

    chained_ids: Set[str] = set()
    for chain in chains:
        for node in chain.nodes:
            chained_ids.add(node.vuln_id)

    isolated = [v["vuln_id"] for v in vulns if v["vuln_id"] not in chained_ids]

    risk_summary = {
        "critical_chains": sum(1 for c in chains if c.severity == ChainSeverity.CRITICAL),
        "high_chains": sum(1 for c in chains if c.severity == ChainSeverity.HIGH),
        "medium_chains": sum(1 for c in chains if c.severity == ChainSeverity.MEDIUM),
        "low_chains": sum(1 for c in chains if c.severity == ChainSeverity.LOW),
        "isolated_vulns": len(isolated),
    }

    recommendations: List[str] = []
    if risk_summary["critical_chains"] > 0:
        recommendations.append(
            f"发现 {risk_summary['critical_chains']} 条严重攻击链，建议立即启动应急响应流程，优先修复相关漏洞。"
        )
    if risk_summary["high_chains"] > 0:
        recommendations.append(
            f"发现 {risk_summary['high_chains']} 条高危攻击链，建议在24小时内完成修复。"
        )
    if len(isolated) > 0:
        recommendations.append(
            f"有 {len(isolated)} 个漏洞暂未关联到攻击链，但仍需逐一评估和修复。"
        )
    if len(chains) >= 3:
        recommendations.append(
            "系统存在多个可组合利用的漏洞，建议进行全面安全加固而非逐个修补。"
        )

    logger.info(
        f"Correlation analysis complete: {len(vulns)} vulns, "
        f"{len(chains)} chains found, {len(isolated)} isolated"
    )

    return CorrelationReport(
        task_id=task_id,
        total_vulns=len(vulns),
        chains_found=len(chains),
        attack_chains=chains,
        isolated_vulns=isolated,
        risk_summary=risk_summary,
        recommendations=recommendations,
    )


def get_chain_by_id(chains: List[AttackChain], chain_id: str) -> Optional[AttackChain]:
    for chain in chains:
        if chain.chain_id == chain_id:
            return chain
    return None


def export_chains_to_dict(report: CorrelationReport) -> Dict[str, Any]:
    return {
        "task_id": report.task_id,
        "total_vulns": report.total_vulns,
        "chains_found": report.chains_found,
        "attack_chains": [
            {
                "chain_id": c.chain_id,
                "name": c.name,
                "description": c.description,
                "category": c.category.value,
                "severity": c.severity.value,
                "confidence": c.confidence,
                "nodes": [
                    {
                        "vuln_id": n.vuln_id,
                        "vuln_name": n.vuln_name,
                        "category": n.category,
                        "risk_level": n.risk_level,
                        "target_url": n.target_url,
                        "role": n.role,
                    }
                    for n in c.nodes
                ],
                "exploit_path": c.exploit_path,
                "impact_summary": c.impact_summary,
                "mitigation_priority": c.mitigation_priority,
                "cwe_ids": c.cwe_ids,
                "attck_techniques": c.attck_techniques,
            }
            for c in report.attack_chains
        ],
        "isolated_vulns": report.isolated_vulns,
        "risk_summary": report.risk_summary,
        "recommendations": report.recommendations,
    }
