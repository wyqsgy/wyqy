import time
import threading
import psutil
import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from app.utils.logger import get_logger

logger = get_logger("perf")


@dataclass
class ScanMetrics:
    task_id: str
    start_time: float = field(default_factory=time.time)
    scanners_total: int = 0
    scanners_completed: int = 0
    scanners_failed: int = 0
    scanners_skipped: int = 0
    vulns_found: int = 0
    requests_sent: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    scanner_times: Dict[str, float] = field(default_factory=dict)
    peak_memory_mb: float = 0.0

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def scanners_per_second(self) -> float:
        if self.elapsed > 0:
            return self.scanners_completed / self.elapsed
        return 0.0

    @property
    def success_rate(self) -> float:
        total = self.scanners_completed + self.scanners_failed
        if total > 0:
            return self.scanners_completed / total * 100
        return 100.0


class PerfCollector:
    _instance: Optional["PerfCollector"] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._metrics: Dict[str, ScanMetrics] = {}
                    cls._instance._global_start = time.time()
                    cls._instance._total_requests = 0
                    cls._instance._total_vulns = 0
                    cls._instance._total_scans = 0
        return cls._instance

    def start_task(self, task_id: str) -> ScanMetrics:
        metrics = ScanMetrics(task_id=task_id)
        self._metrics[task_id] = metrics
        self._total_scans += 1
        return metrics

    def get_metrics(self, task_id: str) -> Optional[ScanMetrics]:
        return self._metrics.get(task_id)

    def record_scanner_result(self, task_id: str, module: str, elapsed: float,
                               success: bool, vulns: int = 0):
        metrics = self._metrics.get(task_id)
        if not metrics:
            return
        metrics.scanner_times[module] = elapsed
        if success:
            metrics.scanners_completed += 1
        else:
            metrics.scanners_failed += 1
        metrics.vulns_found += vulns
        self._total_vulns += vulns

        try:
            process = psutil.Process(os.getpid())
            mem_mb = process.memory_info().rss / 1024 / 1024
            if mem_mb > metrics.peak_memory_mb:
                metrics.peak_memory_mb = mem_mb
        except Exception:
            pass

    def record_request(self, task_id: str, sent_bytes: int = 0, recv_bytes: int = 0):
        metrics = self._metrics.get(task_id)
        if metrics:
            metrics.requests_sent += 1
            metrics.bytes_sent += sent_bytes
            metrics.bytes_received += recv_bytes
        self._total_requests += 1

    def get_summary(self, task_id: str) -> dict:
        metrics = self._metrics.get(task_id)
        if not metrics:
            return {}
        slowest = sorted(metrics.scanner_times.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "task_id": task_id,
            "elapsed_seconds": round(metrics.elapsed, 2),
            "scanners_total": metrics.scanners_total,
            "scanners_completed": metrics.scanners_completed,
            "scanners_failed": metrics.scanners_failed,
            "scanners_skipped": metrics.scanners_skipped,
            "success_rate": round(metrics.success_rate, 1),
            "scanners_per_second": round(metrics.scanners_per_second, 2),
            "vulns_found": metrics.vulns_found,
            "requests_sent": metrics.requests_sent,
            "peak_memory_mb": round(metrics.peak_memory_mb, 1),
            "slowest_scanners": [{"module": m, "time": round(t, 2)} for m, t in slowest],
        }

    def get_global_summary(self) -> dict:
        elapsed = time.time() - self._global_start
        try:
            process = psutil.Process(os.getpid())
            mem_mb = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent(interval=0.1)
        except Exception:
            mem_mb = 0
            cpu_percent = 0

        return {
            "uptime_seconds": round(elapsed, 1),
            "total_scans": self._total_scans,
            "active_scans": len(self._metrics),
            "total_requests": self._total_requests,
            "total_vulns": self._total_vulns,
            "memory_mb": round(mem_mb, 1),
            "cpu_percent": round(cpu_percent, 1),
            "threads": threading.active_count(),
        }

    def cleanup_task(self, task_id: str):
        self._metrics.pop(task_id, None)


perf = PerfCollector()
