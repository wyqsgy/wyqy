"""
Async HTTP Client with Connection Pooling, Rate Limiting, and Caching
Inspired by sqlmap's connection management and nuclei's rawhttp
"""
import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from app.utils.logger import get_logger

logger = get_logger("http_client")

DEFAULT_TIMEOUT = ClientTimeout(total=30, connect=10, sock_read=20)
DEFAULT_POOL_SIZE = 50
DEFAULT_POOL_PER_HOST = 10
DEFAULT_RETRIES = 3
DEFAULT_RATE_LIMIT = 0
DEFAULT_CACHE_TTL = 300


@dataclass
class RateLimiter:
    requests_per_second: float = 0
    _tokens: float = 0
    _last_refill: float = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def acquire(self):
        if self.requests_per_second <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.requests_per_second, self._tokens + elapsed * self.requests_per_second)
            self._last_refill = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.requests_per_second
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


@dataclass
class ResponseCache:
    ttl: int = DEFAULT_CACHE_TTL
    _store: Dict[str, Tuple[float, Any]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _make_key(self, method: str, url: str, headers: dict, body: Optional[bytes]) -> str:
        raw = f"{method}|{url}|{json.dumps(headers, sort_keys=True)}|{body or b''}"
        return hashlib.md5(raw.encode()).hexdigest()

    async def get(self, method: str, url: str, headers: dict, body: Optional[bytes] = None) -> Optional[Any]:
        async with self._lock:
            key = self._make_key(method, url, headers, body)
            if key in self._store:
                ts, value = self._store[key]
                if time.time() - ts < self.ttl:
                    return value
                del self._store[key]
        return None

    async def set(self, method: str, url: str, headers: dict, body: Optional[bytes], value: Any):
        async with self._lock:
            key = self._make_key(method, url, headers, body)
            self._store[key] = (time.time(), value)

    async def clear(self):
        async with self._lock:
            self._store.clear()

    def size(self) -> int:
        return len(self._store)


class AsyncHTTPClient:
    _instance: Optional["AsyncHTTPClient"] = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(
        self,
        pool_size: int = DEFAULT_POOL_SIZE,
        pool_per_host: int = DEFAULT_POOL_PER_HOST,
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_RETRIES,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        proxy: Optional[str] = None,
        user_agents: Optional[List[str]] = None,
        verify_ssl: bool = False,
        allow_redirects: bool = True,
        max_redirects: int = 5,
    ):
        self.pool_size = pool_size
        self.pool_per_host = pool_per_host
        self.timeout = timeout
        self.max_retries = max_retries
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects

        self.rate_limiter = RateLimiter(requests_per_second=rate_limit)
        self.cache = ResponseCache(ttl=cache_ttl)

        self._user_agents = user_agents or [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        ]
        self._ua_index = 0

        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[TCPConnector] = None

        self._stats = {
            "requests": 0,
            "retries": 0,
            "cache_hits": 0,
            "errors": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
        }

    @classmethod
    async def get_instance(cls, **kwargs) -> "AsyncHTTPClient":
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(**kwargs)
                    await cls._instance.start()
        return cls._instance

    async def start(self):
        if self._session is not None:
            return

        connector_kwargs = {
            "limit": self.pool_size,
            "limit_per_host": self.pool_per_host,
            "ssl": self.verify_ssl,
            "force_close": False,
            "enable_cleanup_closed": True,
            "ttl_dns_cache": 300,
        }

        if not self.verify_ssl:
            connector_kwargs["ssl"] = False

        self._connector = TCPConnector(**connector_kwargs)

        timeout_config = aiohttp.ClientTimeout(
            total=self.timeout.total if hasattr(self.timeout, 'total') else 30,
            connect=self.timeout.connect if hasattr(self.timeout, 'connect') else 10,
            sock_read=self.timeout.sock_read if hasattr(self.timeout, 'sock_read') else 20,
        )

        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=timeout_config,
        )

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None
        if self._connector:
            await self._connector.close()
            self._connector = None

    def _rotate_ua(self) -> str:
        ua = self._user_agents[self._ua_index % len(self._user_agents)]
        self._ua_index += 1
        return ua

    def _build_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "User-Agent": self._rotate_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        json_data: Optional[dict] = None,
        params: Optional[Dict[str, str]] = None,
        use_cache: bool = True,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[ClientTimeout] = None,
    ) -> "HTTPResponse":
        if self._session is None:
            await self.start()

        if follow_redirects is None:
            follow_redirects = self.allow_redirects

        req_headers = self._build_headers(headers)

        if use_cache:
            cached = await self.cache.get(method, url, req_headers, data)
            if cached is not None:
                self._stats["cache_hits"] += 1
                return cached

        await self.rate_limiter.acquire()

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                self._stats["requests"] += 1

                kwargs = {
                    "headers": req_headers,
                    "allow_redirects": follow_redirects,
                    "max_redirects": self.max_redirects,
                    "proxy": self.proxy,
                }

                if timeout:
                    kwargs["timeout"] = timeout

                if data:
                    kwargs["data"] = data
                    self._stats["bytes_sent"] += len(data)
                if json_data:
                    kwargs["json"] = json_data
                if params:
                    kwargs["params"] = params

                async with self._session.request(method, url, **kwargs) as resp:
                    body = await resp.read()
                    self._stats["bytes_received"] += len(body)

                    response = HTTPResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        elapsed=0,
                    )

                    if use_cache and resp.status < 400:
                        await self.cache.set(method, url, req_headers, data, response)

                    return response

            except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionError) as e:
                last_error = e
                self._stats["retries"] += 1
                if attempt < self.max_retries:
                    wait = 2 ** attempt * 0.5
                    logger.debug(f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}, retrying in {wait}s")
                    await asyncio.sleep(wait)
                else:
                    self._stats["errors"] += 1
                    logger.error(f"Request failed after {self.max_retries + 1} attempts: {url} - {e}")

        raise last_error or RuntimeError(f"Request failed: {url}")

    async def get(self, url: str, **kwargs) -> "HTTPResponse":
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> "HTTPResponse":
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> "HTTPResponse":
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> "HTTPResponse":
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> "HTTPResponse":
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> "HTTPResponse":
        return await self.request("OPTIONS", url, **kwargs)

    def get_stats(self) -> dict:
        return dict(self._stats)

    def reset_stats(self):
        for key in self._stats:
            self._stats[key] = 0


@dataclass
class HTTPResponse:
    status: int
    headers: Dict[str, str]
    body: bytes
    url: str
    elapsed: float

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return self.body.decode("latin-1")
            except UnicodeDecodeError:
                return self.body.decode("utf-8", errors="replace")

    @property
    def json(self) -> Any:
        return json.loads(self.text)

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")

    @property
    def content_length(self) -> int:
        return int(self.headers.get("Content-Length", 0))

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type.lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type.lower()

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default)

    def __repr__(self) -> str:
        return f"HTTPResponse(status={self.status}, url={self.url}, size={len(self.body)})"


class ConnectionPool:
    def __init__(self, max_connections: int = 100, max_per_host: int = 20):
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self._active: Dict[str, int] = {}
        self._total = 0
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> bool:
        async with self._lock:
            if self._total >= self.max_connections:
                return False
            host_count = self._active.get(host, 0)
            if host_count >= self.max_per_host:
                return False
            self._active[host] = host_count + 1
            self._total += 1
            return True

    async def release(self, host: str):
        async with self._lock:
            self._active[host] = max(0, self._active.get(host, 1) - 1)
            self._total = max(0, self._total - 1)

    @property
    def active_count(self) -> int:
        return self._total


class BatchExecutor:
    def __init__(self, client: AsyncHTTPClient, concurrency: int = 10):
        self.client = client
        self.concurrency = concurrency
        self._semaphore = asyncio.Semaphore(concurrency)

    async def execute(
        self,
        requests: List[Dict[str, Any]],
        on_result: Optional[Callable] = None,
    ) -> List[HTTPResponse]:
        async def _do(req: Dict[str, Any]) -> HTTPResponse:
            async with self._semaphore:
                method = req.get("method", "GET")
                url = req["url"]
                headers = req.get("headers")
                data = req.get("data")
                json_data = req.get("json")
                params = req.get("params")
                use_cache = req.get("use_cache", True)

                result = await self.client.request(
                    method=method, url=url, headers=headers,
                    data=data, json_data=json_data, params=params,
                    use_cache=use_cache,
                )

                if on_result:
                    try:
                        on_result(req, result)
                    except Exception:
                        pass

                return result

        tasks = [_do(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [
            r if not isinstance(r, Exception) else HTTPResponse(0, {}, b"", "", 0)
            for r in results
        ]


async def create_client(
    pool_size: int = DEFAULT_POOL_SIZE,
    rate_limit: float = DEFAULT_RATE_LIMIT,
    proxy: Optional[str] = None,
    **kwargs,
) -> AsyncHTTPClient:
    client = AsyncHTTPClient(
        pool_size=pool_size,
        rate_limit=rate_limit,
        proxy=proxy,
        **kwargs,
    )
    await client.start()
    return client


async def quick_get(url: str, **kwargs) -> HTTPResponse:
    client = await AsyncHTTPClient.get_instance()
    return await client.get(url, **kwargs)


async def quick_post(url: str, **kwargs) -> HTTPResponse:
    client = await AsyncHTTPClient.get_instance()
    return await client.post(url, **kwargs)
