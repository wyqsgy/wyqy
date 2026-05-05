"""
POC-based vulnerability scanner that wraps the POC executor as a BaseScanner.
Enables template-driven vulnerability detection with complex matching logic.
"""
from typing import List, Optional

from app.scanner.base import BaseScanner, VulnResult
from app.core.poc_db import POC, RiskLevel, get_pocs_by_tags, get_all_pocs
from app.core.poc_executor import execute_poc, POCResponse
from app.utils.logger import get_logger

logger = get_logger("poc_scanner")


class POCScanner(BaseScanner):
    """Generic POC-based scanner that can run any POC template."""

    name = "POC模板扫描器"
    description = "基于POC模板的通用漏洞扫描器"
    category = "poc"
    module = "poc_scanner"
    risk_level = "info"
    risk_score = 0

    def __init__(self, target: str, poc: Optional[POC] = None, poc_ids: Optional[List[str]] = None):
        super().__init__(target)
        self._poc = poc
        self._poc_ids = poc_ids or []
        self._proxy = None
        self._timeout = 15

    def set_proxy(self, proxy: str):
        self._proxy = proxy

    def set_timeout(self, timeout: int):
        self._timeout = timeout

    def check(self) -> bool:
        found_any = False

        pocs_to_run: List[POC] = []
        if self._poc:
            pocs_to_run.append(self._poc)
        if self._poc_ids:
            from app.core.poc_db import get_poc
            for pid in self._poc_ids:
                poc = get_poc(pid)
                if poc:
                    pocs_to_run.append(poc)

        for poc in pocs_to_run:
            try:
                matched, extracted_vars, responses = execute_poc(
                    poc, self.target, proxy=self._proxy, timeout=self._timeout
                )
                if matched:
                    found_any = True
                    evidence = ""
                    if responses:
                        last_resp = responses[-1]
                        body_text = last_resp.body.decode("utf-8", errors="replace")[:2000] if last_resp.body else ""
                        evidence = f"HTTP {last_resp.status}\n{body_text}"

                    self.add_result(
                        name=poc.name,
                        target_url=self.target,
                        description=poc.description,
                        detail=f"POC ID: {poc.id}\nCVSS: {poc.cvss_score}\n"
                               f"CVE: {', '.join(poc.cve_ids) if poc.cve_ids else 'N/A'}\n"
                               f"CNVD: {', '.join(poc.cnvd_ids) if poc.cnvd_ids else 'N/A'}",
                        payload=poc.requests[0].path if poc.requests else "",
                        evidence=evidence,
                        raw_data={
                            "poc_id": poc.id,
                            "extracted_vars": extracted_vars,
                            "cve_ids": poc.cve_ids,
                            "cnvd_ids": poc.cnvd_ids,
                            "cvss_score": poc.cvss_score,
                            "references": poc.references,
                        },
                    )
            except Exception as e:
                logger.debug(f"POC {poc.id} check failed: {e}")

        return found_any


class TagBasedPOCScanner(BaseScanner):
    """Scanner that runs all POCs matching specific tags."""

    name = "标签POC扫描器"
    description = "基于标签匹配的POC批量扫描器"
    category = "poc"
    module = "tag_poc_scanner"
    risk_level = "info"
    risk_score = 0

    def __init__(self, target: str, tags: Optional[List[str]] = None,
                 match_all: bool = False, max_pocs: int = 50):
        super().__init__(target)
        self._tags = tags or []
        self._match_all = match_all
        self._max_pocs = max_pocs
        self._proxy = None
        self._timeout = 15

    def set_proxy(self, proxy: str):
        self._proxy = proxy

    def set_timeout(self, timeout: int):
        self._timeout = timeout

    def check(self) -> bool:
        found_any = False

        if self._tags:
            from app.core.poc_db import get_pocs_by_tags
            pocs = get_pocs_by_tags(self._tags, match_all=self._match_all)
        else:
            pocs = get_all_pocs()

        pocs = pocs[:self._max_pocs]

        for poc in pocs:
            try:
                matched, extracted_vars, responses = execute_poc(
                    poc, self.target, proxy=self._proxy, timeout=self._timeout
                )
                if matched:
                    found_any = True
                    evidence = ""
                    if responses:
                        last_resp = responses[-1]
                        body_text = last_resp.body.decode("utf-8", errors="replace")[:2000] if last_resp.body else ""
                        evidence = f"HTTP {last_resp.status}\n{body_text}"

                    self.add_result(
                        name=poc.name,
                        target_url=self.target,
                        description=poc.description,
                        detail=f"POC ID: {poc.id}\nCVSS: {poc.cvss_score}\n"
                               f"Tags: {', '.join(poc.tags)}",
                        payload=poc.requests[0].path if poc.requests else "",
                        evidence=evidence,
                        raw_data={
                            "poc_id": poc.id,
                            "extracted_vars": extracted_vars,
                            "cve_ids": poc.cve_ids,
                            "cnvd_ids": poc.cnvd_ids,
                            "cvss_score": poc.cvss_score,
                            "references": poc.references,
                        },
                    )
            except Exception as e:
                logger.debug(f"POC {poc.id} check failed: {e}")

        return found_any
