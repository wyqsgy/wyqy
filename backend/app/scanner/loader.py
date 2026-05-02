import importlib
import pkgutil
from app.scanner.base import BaseScanner
from app.utils.logger import get_logger

logger = get_logger("loader")

_scanner_registry: dict[str, type[BaseScanner]] = {}


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
