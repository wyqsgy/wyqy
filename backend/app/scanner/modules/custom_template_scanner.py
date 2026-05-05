"""
自定义模板扫描器

加载用户编写的检测模板并在扫描时执行。
"""

from __future__ import annotations

import time
import hashlib
from typing import List, Optional
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.scanner.base import BaseScanner, VulnResult
from app.scanner.loader import register_scanner
from app.core.template_engine import (
    TemplateParser,
    TemplateMatcher,
    TemplateRequest,
    DetectionTemplate,
    MatcherCondition,
)
from app.database import SessionLocal
from app.models.custom_template import CustomTemplate
from app.utils.logger import get_logger

logger = get_logger("template_scanner")


@dataclass
class TemplateResponse:
    status: int
    body: str
    headers: dict
    elapsed: float


@register_scanner
class CustomTemplateScanner(BaseScanner):
    module = "custom-templates"
    name = "自定义检测模板"
    category = "custom"
    severity = "medium"

    def __init__(self, target: str):
        super().__init__(target)
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": "WyqYan/1.0",
            "Accept": "*/*",
        })
        session.verify = False
        session.timeout = 15
        return session

    def run(self) -> List[VulnResult]:
        results: List[VulnResult] = []

        templates = self._load_enabled_templates()
        if not templates:
            logger.debug("No enabled custom templates found")
            return results

        logger.info(f"Executing {len(templates)} custom templates against {self.target}")

        for template in templates:
            try:
                matched = self._execute_template(template)
                if matched:
                    for m in matched:
                        results.append(m)
            except Exception as e:
                logger.warning(f"Template {template.id} execution failed: {e}")

        if results:
            self._update_match_counts(templates, results)

        return results

    def _load_enabled_templates(self) -> List[DetectionTemplate]:
        db = SessionLocal()
        try:
            rows = db.query(CustomTemplate).filter(
                CustomTemplate.enabled == True
            ).all()

            templates = []
            for row in rows:
                try:
                    if row.format == "yaml":
                        template = TemplateParser.parse_yaml(row.content)
                    else:
                        template = TemplateParser.parse_json(row.content)
                    templates.append(template)
                except Exception as e:
                    logger.warning(f"Failed to parse template {row.template_id}: {e}")

            return templates
        finally:
            db.close()

    def _execute_template(self, template: DetectionTemplate) -> List[VulnResult]:
        results: List[VulnResult] = []

        for req_def in template.requests:
            try:
                response = self._send_request(req_def)
                if response is None:
                    continue

                if self._check_matchers(req_def.matchers, req_def.matchers_condition, response):
                    evidence = self._build_evidence(req_def, response, template)
                    vuln_id = hashlib.md5(
                        f"{template.id}:{req_def.method}:{req_def.path}".encode()
                    ).hexdigest()[:16]

                    result = VulnResult(
                        vuln_id=vuln_id,
                        name=template.name,
                        module="custom-templates",
                        category="custom",
                        risk_level=template.severity.value,
                        target_url=self.target,
                        payload=req_def.path,
                        response_snippet=response.body[:500] if response.body else "",
                        evidence=evidence,
                        description=template.description,
                        remediation=self._get_remediation(template),
                    )
                    results.append(result)

            except Exception as e:
                logger.debug(f"Request {req_def.method} {req_def.path} failed: {e}")

        return results

    def _send_request(self, req_def: TemplateRequest) -> Optional[TemplateResponse]:
        url = self.target.rstrip("/") + "/" + req_def.path.lstrip("/")

        try:
            start = time.time()
            resp = self._session.request(
                method=req_def.method.upper(),
                url=url,
                headers={**self._session.headers, **req_def.headers},
                data=req_def.body,
                allow_redirects=req_def.redirects,
                timeout=15,
            )
            elapsed = time.time() - start

            body = resp.text
            if len(body) > 50000:
                body = body[:50000]

            return TemplateResponse(
                status=resp.status_code,
                body=body,
                headers=dict(resp.headers),
                elapsed=elapsed,
            )
        except requests.RequestException as e:
            logger.debug(f"Request to {url} failed: {e}")
            return None

    def _check_matchers(
        self,
        matchers: List[TemplateMatcher],
        condition: MatcherCondition,
        response: TemplateResponse,
    ) -> bool:
        if not matchers:
            return False

        results = []
        for matcher in matchers:
            results.append(matcher.match(response))

        if condition == MatcherCondition.AND:
            return all(results)
        else:
            return any(results)

    def _build_evidence(
        self,
        req_def: TemplateRequest,
        response: TemplateResponse,
        template: DetectionTemplate,
    ) -> str:
        parts = [
            f"模板: {template.id}",
            f"请求: {req_def.method} {req_def.path}",
            f"状态码: {response.status}",
            f"响应大小: {len(response.body)} bytes",
            f"响应时间: {response.elapsed:.2f}s",
        ]

        for matcher in req_def.matchers:
            matched = matcher.match(response)
            parts.append(f"匹配器 [{matcher.type.value}]: {'✓ 命中' if matched else '✗ 未命中'}")

        return "\n".join(parts)

    def _get_remediation(self, template: DetectionTemplate) -> str:
        return template.info.get("remediation", "请根据漏洞类型参考OWASP修复指南进行修复。")

    def _update_match_counts(
        self,
        templates: List[DetectionTemplate],
        results: List[VulnResult],
    ):
        db = SessionLocal()
        try:
            matched_ids = set()
            for r in results:
                for t in templates:
                    if t.name == r.name:
                        matched_ids.add(t.id)

            for tid in matched_ids:
                db.query(CustomTemplate).filter(
                    CustomTemplate.template_id == tid
                ).update({
                    CustomTemplate.match_count: CustomTemplate.match_count + 1,
                    CustomTemplate.last_matched_at: time.time(),
                }, synchronize_session=False)

            db.commit()
        except Exception as e:
            logger.warning(f"Failed to update match counts: {e}")
            db.rollback()
        finally:
            db.close()
