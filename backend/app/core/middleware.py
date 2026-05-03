"""
Middleware Pipeline - Request/Response processing chain
Inspired by sqlmap's tamper chain and nuclei's preprocessing system.
"""
import time
import hashlib
import random
from typing import Any, Callable, Optional
from dataclasses import dataclass, field
from app.utils.logger import get_logger

logger = get_logger("middleware")


@dataclass
class RequestContext:
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Optional[bytes] = None
    params: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    timeout: float = 30.0
    allow_redirects: bool = True
    verify_ssl: bool = False
    metadata: dict = field(default_factory=dict)
    _id: str = field(default_factory=lambda: hashlib.md5(str(random.random()).encode()).hexdigest()[:12])


@dataclass
class ResponseContext:
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    text: str = ""
    elapsed: float = 0.0
    request_ctx: Optional[RequestContext] = None
    metadata: dict = field(default_factory=dict)


class Middleware:
    def __init__(self, name: str = "base"):
        self.name = name
        self._next: Optional[Middleware] = None

    def set_next(self, middleware: "Middleware") -> "Middleware":
        self._next = middleware
        return middleware

    async def process_request(self, ctx: RequestContext) -> RequestContext:
        return ctx

    async def process_response(self, ctx: ResponseContext) -> ResponseContext:
        return ctx

    async def handle(self, ctx: RequestContext, sender: Callable) -> ResponseContext:
        ctx = await self.process_request(ctx)
        if self._next:
            response = await self._next.handle(ctx, sender)
        else:
            response = await sender(ctx)
        response = await self.process_response(response)
        return response


class MiddlewarePipeline:
    def __init__(self):
        self._head: Optional[Middleware] = None
        self._tail: Optional[Middleware] = None
        self._middlewares: list[Middleware] = []

    def add(self, middleware: Middleware) -> "MiddlewarePipeline":
        self._middlewares.append(middleware)
        if self._head is None:
            self._head = middleware
            self._tail = middleware
        else:
            self._tail.set_next(middleware)
            self._tail = middleware
        return self

    def remove(self, name: str) -> "MiddlewarePipeline":
        self._middlewares = [m for m in self._middlewares if m.name != name]
        self._rebuild_chain()
        return self

    def _rebuild_chain(self):
        self._head = None
        self._tail = None
        for mw in self._middlewares:
            if self._head is None:
                self._head = mw
                self._tail = mw
            else:
                self._tail.set_next(mw)
                self._tail = mw

    async def execute(self, ctx: RequestContext, sender: Callable) -> ResponseContext:
        if self._head is None:
            return await sender(ctx)
        return await self._head.handle(ctx, sender)


class RateLimitMiddleware(Middleware):
    def __init__(self, max_rps: float = 10.0):
        super().__init__("rate_limit")
        self.max_rps = max_rps
        self._last_request = 0.0

    async def process_request(self, ctx: RequestContext) -> RequestContext:
        elapsed = time.time() - self._last_request
        if elapsed < 1.0 / self.max_rps:
            await __import__("asyncio").sleep(1.0 / self.max_rps - elapsed)
        self._last_request = time.time()
        return ctx


class UserAgentRotateMiddleware(Middleware):
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]

    def __init__(self):
        super().__init__("ua_rotate")

    async def process_request(self, ctx: RequestContext) -> RequestContext:
        if "User-Agent" not in ctx.headers:
            ctx.headers["User-Agent"] = random.choice(self.USER_AGENTS)
        return ctx


class RetryMiddleware(Middleware):
    def __init__(self, max_retries: int = 3, backoff: float = 1.0):
        super().__init__("retry")
        self.max_retries = max_retries
        self.backoff = backoff

    async def handle(self, ctx: RequestContext, sender: Callable) -> ResponseContext:
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                ctx = await self.process_request(ctx)
                if self._next:
                    response = await self._next.handle(ctx, sender)
                else:
                    response = await sender(ctx)
                response = await self.process_response(response)
                return response
            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    wait = self.backoff * (2 ** attempt)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {wait}s: {e}")
                    await __import__("asyncio").sleep(wait)
        raise last_error


class CacheMiddleware(Middleware):
    def __init__(self, ttl: int = 300):
        super().__init__("cache")
        self._cache: dict[str, tuple[float, ResponseContext]] = {}
        self.ttl = ttl

    def _cache_key(self, ctx: RequestContext) -> str:
        raw = f"{ctx.method}:{ctx.url}:{str(ctx.params)}:{str(ctx.body)}"
        return hashlib.md5(raw.encode()).hexdigest()

    async def handle(self, ctx: RequestContext, sender: Callable) -> ResponseContext:
        key = self._cache_key(ctx)
        if key in self._cache:
            ts, cached = self._cache[key]
            if time.time() - ts < self.ttl:
                return cached
        ctx = await self.process_request(ctx)
        if self._next:
            response = await self._next.handle(ctx, sender)
        else:
            response = await sender(ctx)
        response = await self.process_response(response)
        self._cache[key] = (time.time(), response)
        return response


class RequestLoggerMiddleware(Middleware):
    def __init__(self):
        super().__init__("logger")

    async def process_request(self, ctx: RequestContext) -> RequestContext:
        logger.debug(f"[REQ] {ctx.method} {ctx.url}")
        return ctx

    async def process_response(self, ctx: ResponseContext) -> ResponseContext:
        logger.debug(f"[RES] {ctx.status_code} ({ctx.elapsed:.2f}s) {len(ctx.body)}B")
        return ctx
