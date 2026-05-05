"""
CVSS v3.1 自动计算与漏洞优先级评分引擎

根据漏洞类型、影响范围、利用条件自动计算 CVSS v3.1 评分，
并提供基于风险的优先级排序。

CVSS v3.1 公式参考: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from app.utils.logger import get_logger

logger = get_logger("cvss")


class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class CiaImpact(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class ExploitMaturity(str, Enum):
    NOT_DEFINED = "X"
    UNPROVEN = "U"
    PROOF_OF_CONCEPT = "P"
    FUNCTIONAL = "F"
    HIGH = "H"


class RemediationLevel(str, Enum):
    NOT_DEFINED = "X"
    OFFICIAL_FIX = "O"
    TEMPORARY_FIX = "T"
    WORKAROUND = "W"
    UNAVAILABLE = "U"


class ReportConfidence(str, Enum):
    NOT_DEFINED = "X"
    UNKNOWN = "U"
    REASONABLE = "R"
    CONFIRMED = "C"


class SeverityLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CVSSVector:
    av: AttackVector = AttackVector.NETWORK
    ac: AttackComplexity = AttackComplexity.LOW
    pr: PrivilegesRequired = PrivilegesRequired.NONE
    ui: UserInteraction = UserInteraction.NONE
    s: Scope = Scope.UNCHANGED
    c: CiaImpact = CiaImpact.NONE
    i: CiaImpact = CiaImpact.NONE
    a: CiaImpact = CiaImpact.NONE

    e: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    rl: RemediationLevel = RemediationLevel.NOT_DEFINED
    rc: ReportConfidence = ReportConfidence.NOT_DEFINED

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av.value}/AC:{self.ac.value}/"
            f"PR:{self.pr.value}/UI:{self.ui.value}/S:{self.s.value}/"
            f"C:{self.c.value}/I:{self.i.value}/A:{self.a.value}"
        )

    def to_temporal_string(self) -> str:
        base = self.to_string()
        if self.e != ExploitMaturity.NOT_DEFINED:
            base += f"/E:{self.e.value}"
        if self.rl != RemediationLevel.NOT_DEFINED:
            base += f"/RL:{self.rl.value}"
        if self.rc != ReportConfidence.NOT_DEFINED:
            base += f"/RC:{self.rc.value}"
        return base


WEIGHTS = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.2,
}

AC_WEIGHTS = {
    AttackComplexity.LOW: 0.77,
    AttackComplexity.HIGH: 0.44,
}

PR_WEIGHTS_UNCHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}

PR_WEIGHTS_CHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.50,
}

UI_WEIGHTS = {
    UserInteraction.NONE: 0.85,
    UserInteraction.REQUIRED: 0.62,
}

CIA_WEIGHTS = {
    CiaImpact.NONE: 0.0,
    CiaImpact.LOW: 0.22,
    CiaImpact.HIGH: 0.56,
}


def calculate_cvss(vector: CVSSVector) -> Tuple[float, float, SeverityLevel]:
    """
    计算 CVSS v3.1 基础分、时间分和严重等级。

    Returns:
        (base_score, temporal_score, severity_level)
    """
    iss = 1 - ((1 - CIA_WEIGHTS[vector.c]) * (1 - CIA_WEIGHTS[vector.i]) * (1 - CIA_WEIGHTS[vector.a]))

    if vector.s == Scope.UNCHANGED:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = (
        8.22
        * WEIGHTS[vector.av]
        * AC_WEIGHTS[vector.ac]
        * (PR_WEIGHTS_UNCHANGED[vector.pr] if vector.s == Scope.UNCHANGED else PR_WEIGHTS_CHANGED[vector.pr])
        * UI_WEIGHTS[vector.ui]
    )

    if impact <= 0:
        base_score = 0.0
    elif vector.s == Scope.UNCHANGED:
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    base_score = round(base_score, 1)

    e_weight = {
        ExploitMaturity.NOT_DEFINED: 1.0,
        ExploitMaturity.UNPROVEN: 0.91,
        ExploitMaturity.PROOF_OF_CONCEPT: 0.94,
        ExploitMaturity.FUNCTIONAL: 0.97,
        ExploitMaturity.HIGH: 1.0,
    }

    rl_weight = {
        RemediationLevel.NOT_DEFINED: 1.0,
        RemediationLevel.OFFICIAL_FIX: 0.95,
        RemediationLevel.TEMPORARY_FIX: 0.96,
        RemediationLevel.WORKAROUND: 0.97,
        RemediationLevel.UNAVAILABLE: 1.0,
    }

    rc_weight = {
        ReportConfidence.NOT_DEFINED: 1.0,
        ReportConfidence.UNKNOWN: 0.92,
        ReportConfidence.REASONABLE: 0.96,
        ReportConfidence.CONFIRMED: 1.0,
    }

    temporal_score = round(base_score * e_weight[vector.e] * rl_weight[vector.rl] * rc_weight[vector.rc], 1)

    if base_score == 0:
        severity = SeverityLevel.NONE
    elif base_score < 4.0:
        severity = SeverityLevel.LOW
    elif base_score < 7.0:
        severity = SeverityLevel.MEDIUM
    elif base_score < 9.0:
        severity = SeverityLevel.HIGH
    else:
        severity = SeverityLevel.CRITICAL

    return base_score, temporal_score, severity


VULN_CATEGORY_VECTORS: Dict[str, CVSSVector] = {
    "sql-injection": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.NONE,
    ),
    "rce": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "deserialization": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "file-upload": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.LOW, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "file-read": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.HIGH, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "lfi": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.HIGH, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "xss": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.REQUIRED,
        s=Scope.CHANGED, c=CiaImpact.LOW, i=CiaImpact.LOW, a=CiaImpact.NONE,
    ),
    "csrf": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.REQUIRED,
        s=Scope.CHANGED, c=CiaImpact.LOW, i=CiaImpact.LOW, a=CiaImpact.NONE,
    ),
    "ssrf": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "xxe": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.HIGH, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "idor": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.LOW, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.HIGH, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "auth-bypass": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.NONE,
    ),
    "info-disclosure": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.LOW, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "path-traversal": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.HIGH, i=CiaImpact.NONE, a=CiaImpact.NONE,
    ),
    "command-injection": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "jndi-injection": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "ssti": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "open-redirect": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.REQUIRED,
        s=Scope.CHANGED, c=CiaImpact.LOW, i=CiaImpact.LOW, a=CiaImpact.NONE,
    ),
    "misconfiguration": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.LOW, i=CiaImpact.LOW, a=CiaImpact.NONE,
    ),
    "default-credentials": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
    "exposed-panel": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.UNCHANGED, c=CiaImpact.LOW, i=CiaImpact.LOW, a=CiaImpact.NONE,
    ),
    "cve": CVSSVector(
        av=AttackVector.NETWORK, ac=AttackComplexity.LOW,
        pr=PrivilegesRequired.NONE, ui=UserInteraction.NONE,
        s=Scope.CHANGED, c=CiaImpact.HIGH, i=CiaImpact.HIGH, a=CiaImpact.HIGH,
    ),
}


RISK_LEVEL_TO_SEVERITY: Dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "info": SeverityLevel.NONE,
}


def get_cvss_for_vulnerability(
    category: str,
    risk_level: str = "medium",
    has_auth: bool = False,
    is_exploitable: bool = True,
) -> Dict[str, any]:
    """
    根据漏洞类别自动计算 CVSS 评分。

    Args:
        category: 漏洞类别 (如 sql-injection, rce, xss 等)
        risk_level: 风险等级 (critical/high/medium/low/info)
        has_auth: 是否需要认证
        is_exploitable: 是否存在已知利用方式

    Returns:
        包含 cvss_vector, base_score, temporal_score, severity 的字典
    """
    vector = VULN_CATEGORY_VECTORS.get(category)

    if vector is None:
        severity_map = {
            "critical": (CiaImpact.HIGH, CiaImpact.HIGH, CiaImpact.HIGH),
            "high": (CiaImpact.HIGH, CiaImpact.HIGH, CiaImpact.NONE),
            "medium": (CiaImpact.LOW, CiaImpact.LOW, CiaImpact.NONE),
            "low": (CiaImpact.LOW, CiaImpact.NONE, CiaImpact.NONE),
            "info": (CiaImpact.NONE, CiaImpact.NONE, CiaImpact.NONE),
        }
        c, i, a = severity_map.get(risk_level, (CiaImpact.LOW, CiaImpact.LOW, CiaImpact.NONE))
        vector = CVSSVector(c=c, i=i, a=a)

    if has_auth:
        vector.pr = PrivilegesRequired.LOW

    if is_exploitable:
        vector.e = ExploitMaturity.FUNCTIONAL
    else:
        vector.e = ExploitMaturity.UNPROVEN

    base_score, temporal_score, severity = calculate_cvss(vector)

    return {
        "cvss_vector": vector.to_string(),
        "cvss_temporal_vector": vector.to_temporal_string(),
        "base_score": base_score,
        "temporal_score": temporal_score,
        "severity": severity.value,
        "attack_vector": vector.av.value,
        "attack_complexity": vector.ac.value,
        "privileges_required": vector.pr.value,
        "user_interaction": vector.ui.value,
        "scope": vector.s.value,
        "confidentiality_impact": vector.c.value,
        "integrity_impact": vector.i.value,
        "availability_impact": vector.a.value,
    }


@dataclass
class PriorityScore:
    vuln_id: str
    name: str
    category: str
    risk_level: str
    cvss_base: float
    cvss_temporal: float
    exploit_maturity: str
    has_poc: bool
    is_chained: bool
    chain_severity: str
    business_impact: int
    priority_score: float
    priority_rank: int


def calculate_priority(
    vuln_id: str,
    name: str,
    category: str,
    risk_level: str,
    cvss_base: float,
    cvss_temporal: float,
    has_poc: bool = False,
    is_chained: bool = False,
    chain_severity: str = "",
    business_impact: int = 1,
) -> PriorityScore:
    """
    计算漏洞修复优先级评分。

    综合考虑:
    - CVSS 基础分 (权重 40%)
    - CVSS 时间分 (权重 20%)
    - 是否有 POC (权重 15%)
    - 是否在攻击链中 (权重 15%)
    - 业务影响 (权重 10%)

    Returns:
        PriorityScore 包含优先级评分和排名
    """
    poc_bonus = 15 if has_poc else 0
    chain_bonus = 0
    if is_chained:
        if chain_severity == "critical":
            chain_bonus = 15
        elif chain_severity == "high":
            chain_bonus = 10
        elif chain_severity == "medium":
            chain_bonus = 5

    exploit_maturity = "functional" if has_poc else "unproven"

    priority_score = (
        cvss_base * 4.0
        + cvss_temporal * 2.0
        + poc_bonus
        + chain_bonus
        + business_impact * 1.0
    )

    priority_score = round(priority_score, 1)

    return PriorityScore(
        vuln_id=vuln_id,
        name=name,
        category=category,
        risk_level=risk_level,
        cvss_base=cvss_base,
        cvss_temporal=cvss_temporal,
        exploit_maturity=exploit_maturity,
        has_poc=has_poc,
        is_chained=is_chained,
        chain_severity=chain_severity,
        business_impact=business_impact,
        priority_score=priority_score,
        priority_rank=0,
    )


def rank_vulnerabilities(priorities: List[PriorityScore]) -> List[PriorityScore]:
    """按优先级评分降序排列并分配排名"""
    sorted_priorities = sorted(priorities, key=lambda p: p.priority_score, reverse=True)
    for i, p in enumerate(sorted_priorities):
        p.priority_rank = i + 1
    return sorted_priorities


def get_priority_label(score: float) -> Tuple[str, str]:
    """获取优先级标签和颜色"""
    if score >= 80:
        return "紧急修复", "critical"
    elif score >= 60:
        return "高优先级", "high"
    elif score >= 40:
        return "中优先级", "medium"
    elif score >= 20:
        return "低优先级", "low"
    else:
        return "可延后", "info"
