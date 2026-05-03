import time
import asyncio
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from app.scanner.base import VulnResult
from app.scanner.loader import (
    get_scanners_by_category, get_all_scanners,
    get_scanner_by_module, get_registered_categories,
)
from app.ai.classifier import VulnClassifier
from app.database import SessionLocal
from app.models.task import ScanTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.utils.helper import normalize_url
from app.utils.logger import get_logger
from app.core.finger_map import match_modules, get_module_category

logger = get_logger("engine")
classifier = VulnClassifier()

_executor = ThreadPoolExecutor(max_workers=10)
_running_tasks: dict[str, bool] = {}
_loop: asyncio.AbstractEventLoop | None = None


def _get_loop() -> asyncio.AbstractEventLoop | None:
    global _loop
    if _loop is None or _loop.is_closed():
        try:
            _loop = asyncio.get_event_loop()
        except RuntimeError:
            return None
    return _loop


def _broadcast(task_id: str, event: str, data: dict):
    try:
        from app.ws.manager import ws_manager
        loop = _get_loop()
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_task(task_id, event, data), loop
            )
    except Exception:
        pass


def _resolve_scanner_classes(items: List[str]) -> List[type]:
    """Resolve scanner classes from mixed list of category names and module names."""
    scanner_classes: List[type] = []
    seen_modules: set[str] = set()
    registered_cats = get_registered_categories()

    for item in items:
        item = item.strip()
        if not item:
            continue

        if item in registered_cats:
            for cls in get_scanners_by_category(item):
                if cls.module not in seen_modules:
                    seen_modules.add(cls.module)
                    scanner_classes.append(cls)
        else:
            cls = get_scanner_by_module(item)
            if cls and cls.module not in seen_modules:
                seen_modules.add(cls.module)
                scanner_classes.append(cls)
            else:
                cat = get_module_category(item)
                if cat in registered_cats:
                    for cls in get_scanners_by_category(cat):
                        if cls.module not in seen_modules:
                            seen_modules.add(cls.module)
                            scanner_classes.append(cls)

    return scanner_classes


def start_scan(task_id: str, target: str, categories: list[str],
               fingerprint: Optional[dict] = None):
    _running_tasks[task_id] = True
    future = _executor.submit(
        _run_scan_sync, task_id, target, categories, fingerprint
    )
    return future


def stop_scan(task_id: str):
    _running_tasks[task_id] = False


def _run_scan_sync(task_id: str, target: str, categories: list[str],
                   fingerprint: Optional[dict] = None):
    db = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
        if not task:
            return

        task.status = TaskStatus.RUNNING
        db.commit()
        _broadcast(task_id, "scan_started", {
            "target": target, "status": "running", "categories": categories
        })

        target = normalize_url(target)

        if not categories or "all" in categories:
            all_scanners = get_all_scanners()
            scanner_classes = list(all_scanners.values())
        else:
            scanner_classes = _resolve_scanner_classes(categories)

        if fingerprint:
            fp_modules = set(match_modules(fingerprint))
            scanner_classes = [
                cls for cls in scanner_classes
                if cls.module in fp_modules
            ]
            if not scanner_classes:
                scanner_classes = _resolve_scanner_classes(categories)

        total = len(scanner_classes)
        task.total_checks = total
        db.commit()

        all_results: list[VulnResult] = []
        for idx, scanner_cls in enumerate(scanner_classes):
            if not _running_tasks.get(task_id, False):
                task.status = TaskStatus.STOPPED
                db.commit()
                _broadcast(task_id, "scan_stopped", {"task_id": task_id})
                return

            module_name = scanner_cls.module
            _broadcast(task_id, "scanner_running", {
                "module": module_name,
                "index": idx + 1,
                "total": total,
                "progress": int((idx + 1) / total * 100),
            })

            try:
                scanner = scanner_cls(target)
                results = scanner.run()
                all_results.extend(results)
                task.progress = int((idx + 1) / total * 100)
                db.commit()

                if results:
                    for r in results:
                        _broadcast(task_id, "vuln_found", {
                            "vuln_id": r.vuln_id,
                            "name": r.name,
                            "risk_level": r.risk_level,
                            "module": r.module,
                            "category": r.category,
                        })

                _broadcast(task_id, "progress", {
                    "progress": task.progress,
                    "current_module": module_name,
                    "vulns_found": len(all_results),
                })
            except Exception as e:
                logger.warning(f"Scanner {module_name} failed: {e}")
                task.progress = int((idx + 1) / total * 100)
                db.commit()
                _broadcast(task_id, "scanner_error", {
                    "module": module_name, "error": str(e)
                })

        classified_results = []
        _broadcast(task_id, "ai_analyzing", {"total_vulns": len(all_results)})

        for result in all_results:
            ai_result = classifier.classify(
                response_text=result.response_snippet,
                response_code=0,
                payload=result.payload,
                risk_level=result.risk_level,
            )
            result.raw_data["ai_analysis"] = ai_result
            classified_results.append(result)

            vuln = Vulnerability(
                task_id=task_id,
                vuln_id=result.vuln_id,
                name=result.name,
                category=result.category,
                module=result.module,
                risk_level=result.risk_level,
                risk_score=result.risk_score,
                target_url=result.target_url,
                description=result.description,
                detail=result.detail,
                payload=result.payload,
                request_data=result.request_data,
                response_snippet=result.response_snippet,
                evidence=result.evidence,
                fix_suggestion=result.fix_suggestion,
                cve_ids=result.cve_ids,
                references=result.references,
                ai_analysis=str(ai_result.get("verdict", "")),
                ai_confidence=ai_result.get("confidence", 0),
                is_confirmed=1 if ai_result.get("is_true_positive") else 0,
                raw_data=result.raw_data,
            )
            db.add(vuln)

            if result.risk_level == "critical":
                task.critical_count += 1
            elif result.risk_level == "high":
                task.high_count += 1
            elif result.risk_level == "medium":
                task.medium_count += 1
            elif result.risk_level == "low":
                task.low_count += 1

        task.vuln_count = len(all_results)
        task.status = TaskStatus.COMPLETED
        task.progress = 100
        task.finished_at = datetime.utcnow()
        db.commit()

        _broadcast(task_id, "scan_completed", {
            "task_id": task_id,
            "total_vulns": len(all_results),
            "critical": task.critical_count,
            "high": task.high_count,
            "medium": task.medium_count,
            "low": task.low_count,
            "duration": str(task.finished_at - task.created_at) if task.created_at else None,
        })

        logger.info(f"Task {task_id} completed: {len(all_results)} vulns found")

    except Exception as e:
        logger.error(f"Task {task_id} failed: {e}")
        task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
        if task:
            task.status = TaskStatus.FAILED
            task.error_msg = str(e)
            task.finished_at = datetime.utcnow()
            db.commit()
        _broadcast(task_id, "scan_failed", {"task_id": task_id, "error": str(e)})
    finally:
        _running_tasks.pop(task_id, None)
        db.close()
