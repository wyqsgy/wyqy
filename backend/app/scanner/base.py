from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from app.utils.helper import gen_vuln_id


@dataclass
class VulnResult:
    name: str
    category: str
    module: str
    risk_level: str
    risk_score: int
    target_url: str
    description: str = ""
    detail: str = ""
    payload: str = ""
    request_data: str = ""
    response_snippet: str = ""
    evidence: str = ""
    fix_suggestion: str = ""
    cve_ids: list = field(default_factory=list)
    references: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    vuln_id: str = ""

    def __post_init__(self):
        if not self.vuln_id:
            self.vuln_id = gen_vuln_id()


class BaseScanner(ABC):
    name: str = ""
    description: str = ""
    category: str = ""
    module: str = ""
    risk_level: str = "info"
    risk_score: int = 0
    cve_ids: list = []
    references: list = []
    fix_suggestion: str = ""

    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.results: list[VulnResult] = []

    @abstractmethod
    def check(self) -> bool:
        pass

    def add_result(self, name="", target_url="", description="", detail="",
                   payload="", request_data="", response_snippet="", evidence="",
                   raw_data=None):
        result = VulnResult(
            name=name or self.name,
            category=self.category,
            module=self.module,
            risk_level=self.risk_level,
            risk_score=self.risk_score,
            target_url=target_url or self.target,
            description=description or self.description,
            detail=detail,
            payload=payload,
            request_data=request_data,
            response_snippet=response_snippet[:2000] if response_snippet else "",
            evidence=evidence,
            fix_suggestion=self.fix_suggestion,
            cve_ids=list(self.cve_ids),
            references=list(self.references),
            raw_data=raw_data or {},
        )
        self.results.append(result)
        return result

    def run(self) -> list[VulnResult]:
        try:
            self.check()
        except Exception:
            pass
        return self.results
