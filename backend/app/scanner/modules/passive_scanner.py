"""
Passive Scanner Module - integrates passive traffic analysis into the scanning engine.
Can operate in two modes:
1. Proxy mode: acts as an HTTP proxy to capture and analyze traffic
2. Spider mode: crawls the target and analyzes responses passively
"""
import threading
import time
from typing import List, Optional, Dict

from app.scanner.base import BaseScanner, VulnResult
from app.scanner.loader import register_scanner
from app.scanner.passive.traffic_analyzer import (
    TrafficAnalyzer, PassiveFinding, PassiveRuleSeverity,
)
from app.utils.logger import get_logger

logger = get_logger("passive_scanner")


SEVERITY_MAP = {
    PassiveRuleSeverity.INFO: ("info", 0),
    PassiveRuleSeverity.LOW: ("low", 25),
    PassiveRuleSeverity.MEDIUM: ("medium", 50),
    PassiveRuleSeverity.HIGH: ("high", 75),
    PassiveRuleSeverity.CRITICAL: ("critical", 100),
}


@register_scanner
class PassiveScanner(BaseScanner):
    name = "被动流量分析扫描器"
    description = "分析HTTP流量自动发现安全配置问题和信息泄露，无需发送额外请求"
    category = "passive"
    module = "passive_scanner"
    risk_level = "info"
    risk_score = 0

    def __init__(self, target: str):
        super().__init__(target)
        self._analyzer = TrafficAnalyzer()
        self._findings: List[PassiveFinding] = []

    def check(self) -> bool:
        return True

    def analyze_response(self, status_code: int, headers: Dict[str, str],
                         body: str = "", request_url: str = "",
                         request_method: str = "GET") -> List[PassiveFinding]:
        findings = self._analyzer.analyze_response(
            status_code=status_code,
            headers=headers,
            body=body,
            request_url=request_url,
            request_method=request_method,
        )
        self._findings.extend(findings)

        for finding in findings:
            risk_level, risk_score = SEVERITY_MAP.get(finding.severity, ("info", 0))
            self.add_result(
                name=finding.name,
                target_url=finding.location,
                description=finding.description,
                detail=f"规则ID: {finding.rule_id}\n证据: {finding.evidence}",
                evidence=finding.evidence,
                fix_suggestion=finding.fix_suggestion,
                raw_data={
                    "rule_id": finding.rule_id,
                    "rule_type": finding.rule_type.value,
                    "cwe_id": finding.cwe_id,
                    "owasp_category": finding.owasp_category,
                },
            )

        return findings

    def analyze_request(self, method: str, url: str, headers: Dict[str, str],
                        body: str = "") -> List[PassiveFinding]:
        findings = self._analyzer.analyze_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
        )
        self._findings.extend(findings)

        for finding in findings:
            risk_level, risk_score = SEVERITY_MAP.get(finding.severity, ("info", 0))
            self.add_result(
                name=finding.name,
                target_url=finding.location,
                description=finding.description,
                detail=f"规则ID: {finding.rule_id}\n证据: {finding.evidence}",
                evidence=finding.evidence,
                fix_suggestion=finding.fix_suggestion,
                raw_data={
                    "rule_id": finding.rule_id,
                    "rule_type": finding.rule_type.value,
                    "cwe_id": finding.cwe_id,
                    "owasp_category": finding.owasp_category,
                },
            )

        return findings

    def get_summary(self) -> Dict[str, int]:
        return self._analyzer.get_summary()

    def clear(self):
        self._analyzer.clear()
        self._findings.clear()
        self.results.clear()
