import os
import time
import asyncio
import hashlib
import json
import threading
import heapq
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Dict, Set, Tuple

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
from app.core.tamper import get_intelligent_tamper_selector, TamperChain
from app.attack.waf_engine import detect_waf
from app.core.perf import perf
from app.core.vuln_classifier import classify_vulnerability, get_cwe_info
from app.core.vuln_verifier import quick_verify, VerificationResult
from app.core.correlation_engine import analyze_correlations, export_chains_to_dict
from app.core.cvss_calculator import get_cvss_for_vulnerability, calculate_priority

logger = get_logger("engine")
classifier = VulnClassifier()

_CPU_COUNT = os.cpu_count() or 4
_BASE_WORKERS = min(_CPU_COUNT * 2, 32)
_MAX_WORKERS = min(_CPU_COUNT * 4, 64)
_executor = ThreadPoolExecutor(max_workers=_BASE_WORKERS)
_executor_lock = threading.Lock()
_active_scans = 0
_max_concurrent_scans = max(_CPU_COUNT // 2, 2)
_scan_semaphore = threading.BoundedSemaphore(_max_concurrent_scans)
_running_tasks: dict[str, bool] = {}
_loop: asyncio.AbstractEventLoop | None = None
_scan_progress: Dict[str, dict] = {}
_seen_vulns: Dict[str, Set[str]] = {}
_task_futures: Dict[str, object] = {}

class TaskPriority(IntEnum):
    HIGH = 0
    NORMAL = 1
    LOW = 2

@dataclass(order=True)
class PrioritizedTask:
    priority: int
    enqueue_time: float = field(compare=False)
    task_id: str = field(compare=False)
    target: str = field(compare=False)
    categories: list = field(compare=False)
    fingerprint: Optional[dict] = field(compare=False)
    resume_from: Optional[int] = field(compare=False)

_pending_queue: List[PrioritizedTask] = []
_queue_lock = threading.Lock()
_queue_not_empty = threading.Condition(_queue_lock)
_scheduler_running = False
_scheduler_thread: Optional[threading.Thread] = None

SCAN_MODE_PRIORITY = {
    "quick": TaskPriority.HIGH,
    "full": TaskPriority.NORMAL,
    "stealth": TaskPriority.LOW,
}

def _get_priority_for_task(task_id: str, categories: list) -> TaskPriority:
    if not categories:
        return TaskPriority.NORMAL
    if "critical" in categories or "rce" in categories:
        return TaskPriority.HIGH
    return TaskPriority.NORMAL

def _enqueue_task(task_id: str, target: str, categories: list,
                  fingerprint: Optional[dict] = None,
                  resume_from: Optional[int] = None,
                  priority: Optional[TaskPriority] = None):
    if priority is None:
        priority = _get_priority_for_task(task_id, categories)
    pt = PrioritizedTask(
        priority=int(priority),
        enqueue_time=time.time(),
        task_id=task_id,
        target=target,
        categories=categories,
        fingerprint=fingerprint,
        resume_from=resume_from,
    )
    with _queue_lock:
        heapq.heappush(_pending_queue, pt)
        _queue_not_empty.notify()

def _dequeue_task() -> Optional[PrioritizedTask]:
    with _queue_lock:
        while not _pending_queue:
            _queue_not_empty.wait(timeout=1.0)
            if not _pending_queue:
                continue
        return heapq.heappop(_pending_queue)

def _start_scheduler():
    global _scheduler_running, _scheduler_thread
    if _scheduler_running:
        return
    _scheduler_running = True
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()
    logger.info("Task scheduler started")

def _stop_scheduler():
    global _scheduler_running
    _scheduler_running = False
    with _queue_lock:
        _queue_not_empty.notify_all()

def _scheduler_loop():
    while _scheduler_running:
        try:
            pt = _dequeue_task()
            if pt is None:
                continue
            _scan_semaphore.acquire()
            _running_tasks[pt.task_id] = True
            _seen_vulns[pt.task_id] = set()
            global _active_scans
            _active_scans += 1
            _adjust_workers()
            future = _executor.submit(
                _run_scan_sync, pt.task_id, pt.target, pt.categories,
                pt.fingerprint, pt.resume_from
            )
            _task_futures[pt.task_id] = future
            logger.info(f"Scheduled task {pt.task_id} (priority={pt.priority})")
        except Exception as e:
            logger.error(f"Scheduler error: {e}")

def get_queue_status() -> dict:
    with _queue_lock:
        return {
            "pending": len(_pending_queue),
            "active": _active_scans,
            "max_concurrent": _max_concurrent_scans,
            "pending_tasks": [
                {"task_id": pt.task_id, "priority": pt.priority}
                for pt in sorted(_pending_queue)
            ],
        }


def _adjust_workers():
    global _executor, _BASE_WORKERS
    with _executor_lock:
        target = min(_BASE_WORKERS + _active_scans * 2, _MAX_WORKERS)
        if target != _executor._max_workers:
            old = _executor
            _executor = ThreadPoolExecutor(max_workers=target)
            old.shutdown(wait=False)
            logger.info(f"Worker pool adjusted: {old._max_workers} -> {target}")


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


def _dedup_key(result: VulnResult) -> str:
    raw = f"{result.module}|{result.target_url}|{result.name}|{result.payload}"
    return hashlib.md5(raw.encode()).hexdigest()


def _is_duplicate(task_id: str, result: VulnResult) -> bool:
    key = _dedup_key(result)
    if task_id not in _seen_vulns:
        _seen_vulns[task_id] = set()
    if key in _seen_vulns[task_id]:
        return True
    _seen_vulns[task_id].add(key)
    return False


def save_progress(task_id: str, data: dict):
    _scan_progress[task_id] = {
        **data,
        "timestamp": time.time(),
    }


def load_progress(task_id: str) -> Optional[dict]:
    return _scan_progress.get(task_id)


def start_scan(task_id: str, target: str, categories: list[str],
               fingerprint: Optional[dict] = None, resume_from: Optional[int] = None,
               scan_mode: str = "quick"):
    _start_scheduler()
    priority = SCAN_MODE_PRIORITY.get(scan_mode, TaskPriority.NORMAL)
    _enqueue_task(task_id, target, categories, fingerprint, resume_from, priority)
    logger.info(f"Task {task_id} enqueued (mode={scan_mode}, priority={priority})")


def stop_scan(task_id: str):
    global _active_scans
    _running_tasks[task_id] = False
    save_progress(task_id, {"status": "stopped", "stopped_at": time.time()})
    _active_scans = max(0, _active_scans - 1)
    _adjust_workers()


def get_scan_status(task_id: str) -> Optional[dict]:
    return _scan_progress.get(task_id)


class VulnWriteBuffer:
    def __init__(self, task_id: str, db, flush_size: int = 50, flush_interval: float = 5.0):
        self.task_id = task_id
        self.db = db
        self.flush_size = flush_size
        self.flush_interval = flush_interval
        self._buffer: List[Vulnerability] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._total_written = 0

    def add(self, vuln: Vulnerability):
        with self._lock:
            self._buffer.append(vuln)
        if len(self._buffer) >= self.flush_size:
            self.flush()
        elif time.time() - self._last_flush >= self.flush_interval:
            self.flush()

    def flush(self):
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[:]
            self._buffer.clear()
            self._last_flush = time.time()

        try:
            self.db.bulk_save_objects(batch)
            self.db.commit()
            self._total_written += len(batch)
            logger.debug(f"Flushed {len(batch)} vulns for task {self.task_id} (total: {self._total_written})")
        except Exception as e:
            logger.error(f"Batch flush failed for task {self.task_id}: {e}")
            try:
                self.db.rollback()
                for v in batch:
                    self.db.add(v)
                self.db.commit()
                self._total_written += len(batch)
            except Exception as e2:
                logger.error(f"Fallback write also failed: {e2}")

    def close(self):
        self.flush()
        logger.info(f"Write buffer closed for task {self.task_id}, total written: {self._total_written}")


def _persist_results_to_disk(task_id: str, results: List[VulnResult]):
    try:
        import os as _os
        cache_dir = _os.path.join(_os.path.dirname(__file__), "..", "..", "data", "scan_cache")
        _os.makedirs(cache_dir, exist_ok=True)
        cache_file = _os.path.join(cache_dir, f"{task_id}.json")
        data = [
            {
                "vuln_id": r.vuln_id,
                "name": r.name,
                "category": r.category,
                "module": r.module,
                "risk_level": r.risk_level,
                "risk_score": r.risk_score,
                "target_url": r.target_url,
                "payload": r.payload,
                "evidence": r.evidence,
                "cve_ids": r.cve_ids,
            }
            for r in results
        ]
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.debug(f"Failed to persist results to disk: {e}")


def _run_scan_sync(task_id: str, target: str, categories: list[str],
                   fingerprint: Optional[dict] = None, resume_from: Optional[int] = None):
    global _active_scans
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

        waf_info = None
        tamper_chain = None
        try:
            waf_info = detect_waf(target, timeout=8)
            if waf_info and waf_info.get("waf_detected"):
                waf_name = waf_info.get("waf_name", "")
                confidence = waf_info.get("confidence", 0)
                logger.info(f"WAF detected: {waf_name} (confidence: {confidence}%)")
                selector = get_intelligent_tamper_selector()
                tamper_chain = selector.select(waf_name=waf_name)
                _broadcast(task_id, "waf_detected", {
                    "waf_name": waf_name,
                    "confidence": confidence,
                    "details": waf_info.get("details", ""),
                    "tamper_count": len(tamper_chain) if tamper_chain else 0,
                })
                task.waf_info = waf_info
                db.commit()
            else:
                _broadcast(task_id, "waf_detected", {
                    "waf_detected": False,
                    "message": "未检测到WAF/CDN防护",
                })
        except Exception as e:
            logger.debug(f"WAF detection skipped: {e}")

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

        start_idx = resume_from or 0
        all_results: list[VulnResult] = []
        batch_size = min(_CPU_COUNT, 8)
        completed = start_idx

        for batch_start in range(start_idx, total, batch_size):
            if not _running_tasks.get(task_id, False):
                task.status = TaskStatus.STOPPED
                task.progress = int(completed / total * 100) if total > 0 else 0
                db.commit()
                save_progress(task_id, {
                    "status": "stopped",
                    "progress": task.progress,
                    "current_index": completed,
                    "total": total,
                })
                _broadcast(task_id, "scan_stopped", {"task_id": task_id})
                return

            batch_end = min(batch_start + batch_size, total)
            batch_classes = scanner_classes[batch_start:batch_end]

            with ThreadPoolExecutor(max_workers=len(batch_classes)) as batch_executor:
                future_to_scanner = {}
                for scanner_cls in batch_classes:
                    future = batch_executor.submit(_run_single_scanner, scanner_cls, target, task_id, tamper_chain)
                    future_to_scanner[future] = scanner_cls

                for future in as_completed(future_to_scanner):
                    scanner_cls = future_to_scanner[future]
                    module_name = scanner_cls.module
                    try:
                        results = future.result(timeout=120)
                        new_results = []
                        for r in (results or []):
                            if not _is_duplicate(task_id, r):
                                new_results.append(r)
                        all_results.extend(new_results)

                        if new_results:
                            for r in new_results:
                                _broadcast(task_id, "vuln_found", {
                                    "vuln_id": r.vuln_id,
                                    "name": r.name,
                                    "risk_level": r.risk_level,
                                    "module": r.module,
                                    "category": r.category,
                                })
                    except Exception as e:
                        logger.warning(f"Scanner {module_name} failed: {e}")
                        _broadcast(task_id, "scanner_error", {
                            "module": module_name, "error": str(e)
                        })

            completed = batch_end
            task.progress = int(completed / total * 100) if total > 0 else 0
            db.commit()

            save_progress(task_id, {
                "status": "running",
                "progress": task.progress,
                "current_index": completed,
                "total": total,
                "vulns_found": len(all_results),
            })

            _broadcast(task_id, "progress", {
                "progress": task.progress,
                "batch_completed": f"{completed}/{total}",
                "vulns_found": len(all_results),
            })

        classified_results = []
        _broadcast(task_id, "ai_analyzing", {"total_vulns": len(all_results)})

        write_buffer = VulnWriteBuffer(task_id, db)

        _broadcast(task_id, "verifying", {"total_vulns": len(all_results)})
        verified_count = 0
        false_positive_count = 0

        for result in all_results:
            ai_result = classifier.classify(
                response_text=result.response_snippet,
                response_code=0,
                payload=result.payload,
                risk_level=result.risk_level,
            )
            result.raw_data["ai_analysis"] = ai_result

            classification = classify_vulnerability(
                category=result.category,
                risk_level=result.risk_level,
                cvss_score=float(result.risk_score) / 10.0 if result.risk_score else 0.0,
            )
            result.raw_data["classification"] = classification

            cvss_data = get_cvss_for_vulnerability(
                category=result.category,
                risk_level=result.risk_level,
            )
            result.raw_data["cvss"] = cvss_data

            verif_report = quick_verify(
                target_url=result.target_url,
                category=result.category,
                original_payload=result.payload,
                original_response=result.response_snippet,
                risk_level=result.risk_level,
            )
            result.raw_data["verification"] = {
                "result": verif_report.result.value,
                "confidence_score": verif_report.confidence_score,
                "false_positive_reason": verif_report.false_positive_reason,
                "evidences": [
                    {"strategy": e.strategy.value, "description": e.description, "supports": e.supports_finding}
                    for e in verif_report.evidences
                ],
            }

            verified_count += 1
            if verif_report.result == VerificationResult.FALSE_POSITIVE:
                false_positive_count += 1

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
                cwe_id=classification.get("cwe_id", ""),
                cwe_name=classification.get("cwe_name", ""),
                owasp_category=classification.get("owasp_category", ""),
                capec_ids=classification.get("capec_ids", []),
                cvss_score=int(cvss_data.get("base_score", 0) * 10),
                verification_result=verif_report.result.value,
                confidence_score=verif_report.confidence_score,
                false_positive_reason=verif_report.false_positive_reason,
                verification_evidences=[
                    {"strategy": e.strategy.value, "description": e.description, "supports": e.supports_finding}
                    for e in verif_report.evidences
                ],
                raw_data=result.raw_data,
            )
            write_buffer.add(vuln)

            if result.risk_level == "critical":
                task.critical_count += 1
            elif result.risk_level == "high":
                task.high_count += 1
            elif result.risk_level == "medium":
                task.medium_count += 1
            elif result.risk_level == "low":
                task.low_count += 1

        write_buffer.close()
        _persist_results_to_disk(task_id, all_results)

        task.vuln_count = len(all_results)
        task.status = TaskStatus.COMPLETED
        task.progress = 100
        task.finished_at = datetime.utcnow()
        db.commit()

        save_progress(task_id, {
            "status": "completed",
            "progress": 100,
            "total": total,
            "vulns_found": len(all_results),
        })

        _broadcast(task_id, "scan_completed", {
            "task_id": task_id,
            "total_vulns": len(all_results),
            "critical": task.critical_count,
            "high": task.high_count,
            "medium": task.medium_count,
            "low": task.low_count,
            "verified": verified_count,
            "false_positives": false_positive_count,
            "duration": str(task.finished_at - task.created_at) if task.created_at else None,
        })

        logger.info(f"Task {task_id} completed: {len(all_results)} vulns found")

        if len(all_results) >= 2:
            try:
                vuln_dicts = [
                    {
                        "vuln_id": r.vuln_id,
                        "name": r.name,
                        "category": r.category,
                        "risk_level": r.risk_level,
                        "target_url": r.target_url,
                    }
                    for r in all_results
                ]
                corr_report = analyze_correlations(task_id, vuln_dicts)
                corr_data = export_chains_to_dict(corr_report)
                task.correlation_data = corr_data
                db.commit()

                _broadcast(task_id, "correlation_complete", {
                    "task_id": task_id,
                    "chains_found": corr_report.chains_found,
                    "risk_summary": corr_report.risk_summary,
                })

                logger.info(
                    f"Task {task_id} correlation: {corr_report.chains_found} chains, "
                    f"{corr_report.risk_summary['isolated_vulns']} isolated"
                )
            except Exception as corr_err:
                logger.warning(f"Task {task_id} correlation analysis failed: {corr_err}")

        try:
            priorities = []
            chained_ids = set()
            if task.correlation_data:
                for chain in task.correlation_data.get("attack_chains", []):
                    for node in chain.get("nodes", []):
                        chained_ids.add(node.get("vuln_id", ""))

            for r in all_results:
                cvss_data = r.raw_data.get("cvss", {})
                priority = calculate_priority(
                    vuln_id=r.vuln_id,
                    name=r.name,
                    category=r.category,
                    risk_level=r.risk_level,
                    cvss_base=cvss_data.get("base_score", 0),
                    cvss_temporal=cvss_data.get("temporal_score", 0),
                    has_poc=bool(r.raw_data.get("verification", {}).get("confidence_score", 0) >= 70),
                    is_chained=r.vuln_id in chained_ids,
                    chain_severity="",
                )
                priorities.append(priority)

            from app.core.cvss_calculator import rank_vulnerabilities
            ranked = rank_vulnerabilities(priorities)
            task.priority_data = {
                "ranked": [
                    {
                        "vuln_id": p.vuln_id,
                        "name": p.name,
                        "priority_score": p.priority_score,
                        "priority_rank": p.priority_rank,
                        "cvss_base": p.cvss_base,
                        "is_chained": p.is_chained,
                    }
                    for p in ranked[:20]
                ],
                "urgent_count": sum(1 for p in ranked if p.priority_score >= 80),
                "high_priority_count": sum(1 for p in ranked if 60 <= p.priority_score < 80),
            }
            db.commit()
            logger.info(f"Task {task_id} priority ranking: {len(ranked)} vulns ranked")
        except Exception as pri_err:
            logger.warning(f"Task {task_id} priority calculation failed: {pri_err}")

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
        _seen_vulns.pop(task_id, None)
        _task_futures.pop(task_id, None)
        _active_scans = max(0, _active_scans - 1)
        _adjust_workers()
        db.close()


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures: Dict[str, int] = {}
        self._last_failure_time: Dict[str, float] = {}
        self._state: Dict[str, str] = {}
        self._lock = threading.Lock()

    def is_open(self, key: str) -> bool:
        with self._lock:
            if key not in self._state or self._state[key] != "open":
                return False
            if time.time() - self._last_failure_time.get(key, 0) >= self.recovery_timeout:
                self._state[key] = "half_open"
                logger.info(f"Circuit breaker for {key} -> half_open")
                return False
            return True

    def record_success(self, key: str):
        with self._lock:
            self._failures[key] = 0
            self._state[key] = "closed"

    def record_failure(self, key: str):
        with self._lock:
            self._failures[key] = self._failures.get(key, 0) + 1
            self._last_failure_time[key] = time.time()
            if self._failures[key] >= self.failure_threshold:
                self._state[key] = "open"
                logger.warning(f"Circuit breaker OPEN for {key} ({self._failures[key]} failures)")

    def get_state(self, key: str) -> str:
        with self._lock:
            return self._state.get(key, "closed")


_circuit_breaker = CircuitBreaker()


def _run_single_scanner(scanner_cls, target: str, task_id: str,
                        tamper_chain: Optional[TamperChain] = None) -> List[VulnResult]:
    module_name = scanner_cls.module

    if _circuit_breaker.is_open(module_name):
        logger.warning(f"Circuit breaker open for {module_name}, skipping")
        perf.record_scanner_result(task_id, module_name, 0, False)
        return []

    start = time.time()
    try:
        scanner = scanner_cls(target)
        if tamper_chain:
            scanner.set_tamper_chain(tamper_chain)
        results = scanner.run()
        elapsed = time.time() - start
        _circuit_breaker.record_success(module_name)
        perf.record_scanner_result(task_id, module_name, elapsed, True, len(results or []))
        return results
    except Exception as e:
        elapsed = time.time() - start
        _circuit_breaker.record_failure(module_name)
        perf.record_scanner_result(task_id, module_name, elapsed, False)
        logger.warning(f"Scanner {module_name} failed: {e}")
        return []
