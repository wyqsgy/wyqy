"""
POC Executor - Multi-step request execution engine with variable interpolation
Supports complex matching logic with matcher groups, extractors, and chained requests.
"""
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.poc_db import (
    POC, POCRequest, Matcher, MatcherGroup, MatcherCondition,
    MatcherType, Extractor, RiskLevel, get_poc, match_poc_cached,
)
from app.utils.logger import get_logger

logger = get_logger("poc_executor")

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_RETRIES = 2


def _build_session(proxy: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=DEFAULT_RETRIES,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.max_redirects = DEFAULT_MAX_REDIRECTS
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    return session


class POCResponse:
    def __init__(self, status: int, body: bytes, headers: Dict[str, str],
                 elapsed: float = 0, cookies: Optional[Dict[str, str]] = None):
        self.status = status
        self.body = body
        self.headers = headers
        self.elapsed = elapsed
        self.cookies = cookies or {}


def _execute_request(
    session: requests.Session,
    base_url: str,
    poc_request: POCRequest,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[POCResponse]:
    url = urllib.parse.urljoin(base_url, poc_request.path)
    method = poc_request.method.upper()
    headers = dict(poc_request.headers) if poc_request.headers else {}
    body = poc_request.body

    try:
        if method == "GET":
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        elif method == "POST":
            if body:
                resp = session.post(url, data=body.encode("utf-8") if isinstance(body, str) else body,
                                    headers=headers, timeout=timeout, allow_redirects=True)
            else:
                resp = session.post(url, headers=headers, timeout=timeout, allow_redirects=True)
        elif method == "PUT":
            resp = session.put(url, data=body.encode("utf-8") if isinstance(body, str) else body,
                               headers=headers, timeout=timeout, allow_redirects=True)
        elif method == "DELETE":
            resp = session.delete(url, headers=headers, timeout=timeout, allow_redirects=True)
        elif method == "PATCH":
            resp = session.patch(url, data=body.encode("utf-8") if isinstance(body, str) else body,
                                 headers=headers, timeout=timeout, allow_redirects=True)
        elif method == "HEAD":
            resp = session.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        elif method == "OPTIONS":
            resp = session.options(url, headers=headers, timeout=timeout, allow_redirects=True)
        else:
            resp = session.request(method, url, data=body, headers=headers,
                                   timeout=timeout, allow_redirects=True)

        return POCResponse(
            status=resp.status_code,
            body=resp.content,
            headers=dict(resp.headers),
            elapsed=resp.elapsed.total_seconds(),
            cookies=dict(resp.cookies),
        )
    except requests.Timeout:
        logger.debug(f"Timeout: {method} {url}")
        return None
    except requests.ConnectionError:
        logger.debug(f"Connection error: {method} {url}")
        return None
    except Exception as e:
        logger.debug(f"Request failed: {method} {url} - {e}")
        return None


def execute_poc(
    poc: POC,
    base_url: str,
    proxy: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, Optional[Dict[str, str]], List[POCResponse]]:
    """
    Execute a POC against a target URL.
    Supports multi-step requests with variable interpolation between steps.

    Returns:
        Tuple of (matched: bool, extracted_vars: dict, responses: list)
    """
    session = _build_session(proxy=proxy, timeout=timeout)
    responses: List[POCResponse] = []
    accumulated_vars: Dict[str, str] = {}

    requests_to_execute = poc.get_requests()

    for i, poc_req in enumerate(requests_to_execute):
        if accumulated_vars:
            interpolated_req = POCRequest(
                method=poc_req.method,
                path=poc.interpolate(poc_req.path, accumulated_vars),
                headers={k: poc.interpolate(v, accumulated_vars) for k, v in poc_req.headers.items()},
                body=poc.interpolate(poc_req.body, accumulated_vars) if poc_req.body else None,
            )
        else:
            interpolated_req = poc_req

        response = _execute_request(session, base_url, interpolated_req, timeout)
        if response is None:
            if i == 0:
                return False, None, responses
            continue

        responses.append(response)

        if poc.extractors:
            for extractor in poc.extractors:
                value = extractor.extract(response)
                if value is not None:
                    accumulated_vars[extractor.name] = value

    if not responses:
        return False, None, responses

    last_response = responses[-1]
    matched = poc.match(last_response)

    if matched:
        logger.info(f"POC {poc.id} matched on {base_url}")

    return matched, accumulated_vars if accumulated_vars else None, responses


def execute_poc_by_id(
    poc_id: str,
    base_url: str,
    proxy: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, Optional[Dict[str, str]], List[POCResponse]]:
    poc = get_poc(poc_id)
    if poc is None:
        logger.warning(f"POC not found: {poc_id}")
        return False, None, []
    return execute_poc(poc, base_url, proxy, timeout)


def execute_pocs_batch(
    poc_ids: List[str],
    base_url: str,
    proxy: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_concurrent: int = 10,
) -> Dict[str, Tuple[bool, Optional[Dict[str, str]]]]:
    """
    Execute multiple POCs against a target URL concurrently.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: Dict[str, Tuple[bool, Optional[Dict[str, str]]]] = {}

    with ThreadPoolExecutor(max_workers=min(max_concurrent, len(poc_ids))) as executor:
        future_to_poc = {
            executor.submit(execute_poc_by_id, pid, base_url, proxy, timeout): pid
            for pid in poc_ids
        }
        for future in as_completed(future_to_poc):
            poc_id = future_to_poc[future]
            try:
                matched, vars_, _ = future.result(timeout=timeout + 5)
                results[poc_id] = (matched, vars_)
            except Exception as e:
                logger.debug(f"POC {poc_id} execution failed: {e}")
                results[poc_id] = (False, None)

    return results


def quick_match_response(poc: POC, response: POCResponse) -> bool:
    """Quick single-response match without making requests."""
    return poc.match(response)
