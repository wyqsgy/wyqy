"""
自定义检测模板引擎

支持用户编写 YAML/JSON 格式的检测模板，实现自定义漏洞检测规则。
模板格式参考 Nuclei Templates，但做了简化和中文适配。

模板示例:
```yaml
id: my-custom-check
info:
  name: 自定义检测
  severity: high
  description: 检测特定漏洞

requests:
  - method: GET
    path: /api/{{.endpoint}}
    headers:
      User-Agent: WyqYan/1.0

    matchers:
      - type: word
        words:
          - "success"
        condition: and

      - type: status
        status:
          - 200
```

支持的匹配器类型:
- word: 关键词匹配
- regex: 正则表达式匹配
- status: HTTP状态码匹配
- size: 响应大小匹配
- header: 响应头匹配
- time: 响应时间匹配
- hash: 响应体哈希匹配 (md5/sha256)
- dsl: 表达式匹配 (支持简单表达式)
"""

from __future__ import annotations

import re
import json
import hashlib
import time as time_module
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Union
from pathlib import Path

import yaml

from app.utils.logger import get_logger

logger = get_logger(__name__)


class TemplateSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MatcherType(str, Enum):
    WORD = "word"
    REGEX = "regex"
    STATUS = "status"
    SIZE = "size"
    HEADER = "header"
    TIME = "time"
    HASH = "hash"
    DSL = "dsl"


class MatcherCondition(str, Enum):
    AND = "and"
    OR = "or"


class MatcherPart(str, Enum):
    BODY = "body"
    HEADER = "header"
    ALL = "all"


@dataclass
class TemplateMatcher:
    type: MatcherType
    words: Optional[List[str]] = None
    regex: Optional[List[str]] = None
    status: Optional[List[int]] = None
    size: Optional[List[int]] = None
    header: Optional[str] = None
    time: Optional[int] = None
    hash: Optional[str] = None
    dsl: Optional[List[str]] = None
    part: MatcherPart = MatcherPart.BODY
    condition: MatcherCondition = MatcherCondition.AND
    negative: bool = False
    _compiled_regex: List[Any] = field(default_factory=list, repr=False)

    def __post_init__(self):
        if self.regex:
            for pattern in self.regex:
                try:
                    self._compiled_regex.append(re.compile(pattern, re.IGNORECASE | re.DOTALL))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                    self._compiled_regex.append(None)

    def match(self, response: Any) -> bool:
        try:
            results = []

            if self.type == MatcherType.WORD and self.words:
                text = self._get_text(response)
                for word in self.words:
                    results.append(str(word) in text)

            elif self.type == MatcherType.REGEX and self._compiled_regex:
                text = self._get_text(response)
                for compiled in self._compiled_regex:
                    if compiled is None:
                        results.append(False)
                    else:
                        results.append(bool(compiled.search(text)))

            elif self.type == MatcherType.STATUS and self.status:
                for s in self.status:
                    results.append(response.status == s)

            elif self.type == MatcherType.SIZE and self.size:
                body_len = len(getattr(response, "body", b"") or b"")
                for s in self.size:
                    results.append(body_len == s)

            elif self.type == MatcherType.HEADER and self.header:
                headers = getattr(response, "headers", {}) or {}
                results.append(self.header in str(headers))

            elif self.type == MatcherType.TIME and self.time is not None:
                elapsed = getattr(response, "elapsed", 0) or 0
                results.append(elapsed >= self.time)

            elif self.type == MatcherType.HASH and self.hash:
                body = getattr(response, "body", b"") or b""
                if isinstance(body, str):
                    body = body.encode("utf-8")
                computed = hashlib.md5(body).hexdigest()
                results.append(computed == self.hash)

            elif self.type == MatcherType.DSL and self.dsl:
                for expr in self.dsl:
                    results.append(self._eval_dsl(expr, response))

            if not results:
                return False

            if self.condition == MatcherCondition.AND:
                result = all(results)
            else:
                result = any(results)

            return not result if self.negative else result

        except Exception as e:
            logger.debug(f"Matcher error: {e}")
            return False

    def _get_text(self, response: Any) -> str:
        if self.part == MatcherPart.HEADER:
            return str(getattr(response, "headers", {}))
        elif self.part == MatcherPart.ALL:
            body = getattr(response, "body", "") or ""
            headers = str(getattr(response, "headers", {}))
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            return headers + "\n" + body
        else:
            text = getattr(response, "body", "") or ""
            if isinstance(text, bytes):
                text = text.decode("utf-8", errors="replace")
            return text

    def _eval_dsl(self, expr: str, response: Any) -> bool:
        try:
            body = getattr(response, "body", "") or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            status = response.status
            headers = getattr(response, "headers", {}) or {}
            body_len = len(body)

            safe_builtins = {
                "len": len,
                "str": str,
                "int": int,
                "bool": bool,
                "contains": lambda s, sub: sub in str(s),
                "regex": lambda s, p: bool(re.search(p, str(s))),
            }

            local_vars = {
                "body": body,
                "status": status,
                "headers": headers,
                "body_len": body_len,
                **safe_builtins,
            }

            result = eval(expr, {"__builtins__": {}}, local_vars)
            return bool(result)
        except Exception as e:
            logger.debug(f"DSL eval error for '{expr}': {e}")
            return False


@dataclass
class TemplateRequest:
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    matchers: List[TemplateMatcher] = field(default_factory=list)
    matchers_condition: MatcherCondition = MatcherCondition.AND
    extractors: List[Dict[str, Any]] = field(default_factory=list)
    redirects: bool = True
    max_redirects: int = 5


@dataclass
class DetectionTemplate:
    id: str
    info: Dict[str, Any]
    requests: List[TemplateRequest] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.info.get("name", self.id)

    @property
    def severity(self) -> TemplateSeverity:
        sev = self.info.get("severity", "info")
        try:
            return TemplateSeverity(sev)
        except ValueError:
            return TemplateSeverity.INFO

    @property
    def description(self) -> str:
        return self.info.get("description", "")

    @property
    def tags(self) -> List[str]:
        return self.info.get("tags", [])

    @property
    def references(self) -> List[str]:
        return self.info.get("references", [])


class TemplateParser:
    """解析 YAML/JSON 格式的检测模板"""

    @staticmethod
    def parse_yaml(content: str) -> DetectionTemplate:
        try:
            data = yaml.safe_load(content)
            return TemplateParser._parse_dict(data)
        except yaml.YAMLError as e:
            raise ValueError(f"YAML解析失败: {e}")

    @staticmethod
    def parse_json(content: str) -> DetectionTemplate:
        try:
            data = json.loads(content)
            return TemplateParser._parse_dict(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON解析失败: {e}")

    @staticmethod
    def parse_file(filepath: str) -> DetectionTemplate:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"模板文件不存在: {filepath}")

        content = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            return TemplateParser.parse_yaml(content)
        elif path.suffix == ".json":
            return TemplateParser.parse_json(content)
        else:
            raise ValueError(f"不支持的模板格式: {path.suffix}")

    @staticmethod
    def _parse_dict(data: Dict[str, Any]) -> DetectionTemplate:
        if "id" not in data:
            raise ValueError("模板缺少必需字段: id")

        template_id = data["id"]
        info = data.get("info", {})

        requests = []
        for req_data in data.get("requests", []):
            matchers = []
            for m_data in req_data.get("matchers", []):
                matcher = TemplateMatcher(
                    type=MatcherType(m_data.get("type", "word")),
                    words=m_data.get("words"),
                    regex=m_data.get("regex"),
                    status=m_data.get("status"),
                    size=m_data.get("size"),
                    header=m_data.get("header"),
                    time=m_data.get("time"),
                    hash=m_data.get("hash"),
                    dsl=m_data.get("dsl"),
                    part=MatcherPart(m_data.get("part", "body")),
                    condition=MatcherCondition(m_data.get("condition", "and")),
                    negative=m_data.get("negative", False),
                )
                matchers.append(matcher)

            request = TemplateRequest(
                method=req_data.get("method", "GET"),
                path=req_data.get("path", "/"),
                headers=req_data.get("headers", {}),
                body=req_data.get("body"),
                matchers=matchers,
                matchers_condition=MatcherCondition(
                    req_data.get("matchers-condition", "and")
                ),
                extractors=req_data.get("extractors", []),
                redirects=req_data.get("redirects", True),
                max_redirects=req_data.get("max-redirects", 5),
            )
            requests.append(request)

        return DetectionTemplate(
            id=template_id,
            info=info,
            requests=requests,
            variables=data.get("variables", {}),
        )


class TemplateValidator:
    """模板验证器 - 检查模板格式是否正确"""

    REQUIRED_FIELDS = ["id", "info"]
    INFO_REQUIRED = ["name", "severity"]
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    VALID_MATCHER_TYPES = {"word", "regex", "status", "size", "header", "time", "hash", "dsl"}
    VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

    @staticmethod
    def validate(template: DetectionTemplate) -> List[str]:
        errors = []

        if not template.id or not template.id.strip():
            errors.append("模板ID不能为空")
        elif not re.match(r'^[a-zA-Z0-9_-]+$', template.id):
            errors.append("模板ID只能包含字母、数字、下划线和连字符")

        if not template.info:
            errors.append("缺少info字段")
        else:
            if not template.info.get("name"):
                errors.append("缺少info.name字段")
            severity = template.info.get("severity", "")
            if severity not in TemplateValidator.VALID_SEVERITIES:
                errors.append(f"无效的severity值: {severity}，有效值: {TemplateValidator.VALID_SEVERITIES}")

        if not template.requests:
            errors.append("至少需要一个请求定义")
        else:
            for i, req in enumerate(template.requests):
                if req.method.upper() not in TemplateValidator.VALID_METHODS:
                    errors.append(f"请求{i+1}: 无效的HTTP方法 '{req.method}'")
                if not req.path:
                    errors.append(f"请求{i+1}: path不能为空")
                if not req.matchers:
                    errors.append(f"请求{i+1}: 至少需要一个匹配器")
                else:
                    for j, matcher in enumerate(req.matchers):
                        if matcher.type.value not in TemplateValidator.VALID_MATCHER_TYPES:
                            errors.append(f"请求{i+1}匹配器{j+1}: 无效的匹配器类型 '{matcher.type.value}'")

        return errors


def build_template_example() -> str:
    """生成模板示例"""
    return """id: example-sql-injection
info:
  name: SQL注入检测示例
  severity: high
  description: 检测GET参数中的SQL注入漏洞
  tags:
    - sql-injection
    - sqli
  references:
    - https://owasp.org/www-community/attacks/SQL_Injection

requests:
  - method: GET
    path: /api/users?id=1' OR '1'='1
    headers:
      User-Agent: WyqYan/1.0

    matchers:
      - type: word
        words:
          - "mysql"
          - "syntax error"
          - "SQL syntax"
        condition: or

      - type: status
        status:
          - 200
          - 500

    matchers-condition: or
"""
