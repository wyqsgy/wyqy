import logging
import logging.handlers
import os
import sys
import json
import threading
from datetime import datetime
from typing import Optional


_log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
_initialized = False
_init_lock = threading.Lock()


def _ensure_log_dir():
    os.makedirs(_log_dir, exist_ok=True)


class AuditFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, "audit_data"):
            audit = record.audit_data
            record.audit_json = json.dumps(audit, ensure_ascii=False, default=str)
        return super().format(record)


def get_logger(name="wyqyan"):
    global _initialized
    logger = logging.getLogger(name)
    if not logger.handlers:
        with _init_lock:
            if logger.handlers:
                return logger
            _ensure_log_dir()
            logger.setLevel(logging.DEBUG)

            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_fmt = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            console_handler.setFormatter(console_fmt)
            logger.addHandler(console_handler)

            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(_log_dir, "wyqyan.log"),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] [%(filename)s:%(lineno)d] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)

            audit_handler = logging.handlers.RotatingFileHandler(
                os.path.join(_log_dir, "audit.log"),
                maxBytes=10 * 1024 * 1024,
                backupCount=10,
                encoding="utf-8",
            )
            audit_handler.setLevel(logging.INFO)
            audit_fmt = AuditFormatter(
                "[%(asctime)s] [AUDIT] %(audit_json)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            audit_handler.setFormatter(audit_fmt)
            audit_handler.addFilter(lambda r: hasattr(r, "audit_data"))
            logger.addHandler(audit_handler)

            error_handler = logging.handlers.RotatingFileHandler(
                os.path.join(_log_dir, "error.log"),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(file_fmt)
            logger.addHandler(error_handler)

            _initialized = True

    return logger


def audit_log(logger, action: str, target: str = "", detail: str = "",
              task_id: str = "", user: str = "system"):
    extra = {
        "audit_data": {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "target": target,
            "detail": detail,
            "task_id": task_id,
            "user": user,
        }
    }
    logger.info(f"AUDIT: {action} | target={target} | {detail}", extra=extra)


def get_audit_logger():
    return get_logger("audit")
