import uuid
import hashlib
from datetime import datetime


def gen_id(prefix=""):
    short = uuid.uuid4().hex[:12]
    return f"{prefix}{short}" if prefix else short


def gen_task_id():
    return gen_id("task_")


def gen_vuln_id():
    return gen_id("vuln_")


def gen_report_id():
    return gen_id("rpt_")


def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
