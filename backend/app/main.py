from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, init_db
from app.api import tasks, vulnerabilities, reports, scans, recon, attack, templates, settings, pocs, verify, export, ws, cve, correlation
from app.middleware.exceptions import ExceptionMiddleware
from app.middleware.request_logger import RequestLoggerMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    await init_db()
    yield
    await engine.dispose()


app = FastAPI(
    title="Superpowers Security Scanner API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(ExceptionMiddleware)

app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(recon.router, prefix="/api/recon", tags=["recon"])
app.include_router(attack.router, prefix="/api/attack", tags=["attack"])
app.include_router(templates.router, prefix="/api/templates", tags=["templates"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])
app.include_router(pocs.router, prefix="/api/pocs", tags=["pocs"])
app.include_router(verify.router, prefix="/api/verify", tags=["verify"])
app.include_router(export.router, prefix="/api/export", tags=["export"])
app.include_router(ws.router, prefix="/ws", tags=["websocket"])
app.include_router(cve.router, prefix="/api/cve", tags=["cve"])
app.include_router(correlation.router, prefix="/api/correlation", tags=["correlation"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/")
async def root():
    return {"message": "Superpowers Security Scanner API", "version": "2.0.0"}
