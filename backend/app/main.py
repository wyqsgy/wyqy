import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db
from app.api import tasks, scans, reports
from app.utils.logger import get_logger

logger = get_logger("wyqy")

app = FastAPI(
    title="wyqY",
    description="AI驱动的框架/中间件漏洞集合自动化验证平台",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tasks.router)
app.include_router(scans.router)
app.include_router(reports.router)


@app.on_event("startup")
def startup():
    init_db()
    logger.info("wyqY started successfully")


@app.get("/")
def root():
    return {
        "name": "wyqY",
        "version": "1.0.0",
        "description": "AI驱动的框架/中间件漏洞集合自动化验证平台",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
