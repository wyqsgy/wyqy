import importlib
import pkgutil
import os
import time
import threading
from typing import Dict, Optional
from app.scanner.base import BaseScanner
from app.utils.logger import get_logger

logger = get_logger("loader")

_scanner_registry: dict[str, type[BaseScanner]] = {}
_module_mtimes: Dict[str, float] = {}
_reload_lock = threading.Lock()
_watchdog_running = False
_watchdog_thread: Optional[threading.Thread] = None


def register_scanner(cls: type[BaseScanner]):
    key = f"{cls.category}.{cls.module}"
    _scanner_registry[key] = cls
    return cls


def get_all_scanners() -> dict[str, type[BaseScanner]]:
    if not _scanner_registry:
        _load_modules()
    return _scanner_registry


def get_scanners_by_category(category: str) -> list[type[BaseScanner]]:
    if not _scanner_registry:
        _load_modules()
    return [cls for key, cls in _scanner_registry.items() if cls.category == category]


def get_scanner_by_module(module: str) -> type[BaseScanner] | None:
    if not _scanner_registry:
        _load_modules()
    for key, cls in _scanner_registry.items():
        if cls.module == module:
            return cls
    return None


def _load_modules():
    import app.scanner.modules as modules_pkg
    for importer, modname, ispkg in pkgutil.walk_packages(
        modules_pkg.__path__, prefix=modules_pkg.__name__ + "."
    ):
        try:
            importlib.import_module(modname)
        except Exception as e:
            logger.warning(f"Failed to load module {modname}: {e}")


def get_registered_categories() -> dict[str, list[str]]:
    if not _scanner_registry:
        _load_modules()
    cats: dict[str, list[str]] = {}
    for key, cls in _scanner_registry.items():
        cats.setdefault(cls.category, []).append(cls.module)
    return cats


def reload_modules() -> Dict[str, bool]:
    with _reload_lock:
        import app.scanner.modules as modules_pkg
        results = {}
        for importer, modname, ispkg in pkgutil.walk_packages(
            modules_pkg.__path__, prefix=modules_pkg.__name__ + "."
        ):
            try:
                module = importlib.import_module(modname)
                module_file = getattr(module, "__file__", None)
                if module_file and module_file.endswith(".py"):
                    current_mtime = os.path.getmtime(module_file)
                    if modname in _module_mtimes and _module_mtimes[modname] >= current_mtime:
                        results[modname] = False
                        continue
                    _module_mtimes[modname] = current_mtime
                importlib.reload(module)
                results[modname] = True
                logger.info(f"Hot-reloaded module: {modname}")
            except Exception as e:
                results[modname] = False
                logger.warning(f"Failed to reload module {modname}: {e}")
        return results


def start_hot_reload_watchdog(interval: float = 5.0):
    global _watchdog_running, _watchdog_thread
    if _watchdog_running:
        return
    _watchdog_running = True
    _watchdog_thread = threading.Thread(target=_watchdog_loop, args=(interval,), daemon=True)
    _watchdog_thread.start()
    logger.info(f"Hot-reload watchdog started (interval={interval}s)")


def stop_hot_reload_watchdog():
    global _watchdog_running
    _watchdog_running = False


def _watchdog_loop(interval: float):
    while _watchdog_running:
        time.sleep(interval)
        try:
            changed = reload_modules()
            reloaded = [k for k, v in changed.items() if v]
            if reloaded:
                logger.info(f"Watchdog reloaded {len(reloaded)} modules: {reloaded}")
        except Exception as e:
            logger.error(f"Watchdog error: {e}")
