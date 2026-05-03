"""
Plugin Registry System - Nuclei-style protocol abstraction
Allows dynamic registration of scanners, recon modules, and attack engines.
"""
from typing import Dict, Type, Any, Callable, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class PluginType(Enum):
    SCANNER = "scanner"
    RECON = "recon"
    ATTACK = "attack"
    TAMPER = "tamper"
    EXPORTER = "exporter"
    MIDDLEWARE = "middleware"


@dataclass
class PluginMeta:
    name: str
    plugin_type: PluginType
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    category: str = "general"
    risk_level: str = "info"
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    enabled: bool = True
    priority: int = 100


class PluginRegistry:
    _instance = None
    _plugins: Dict[str, Any] = {}
    _meta: Dict[str, PluginMeta] = {}
    _hooks: Dict[str, List[Callable]] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def register(cls, plugin_class: Type, meta: PluginMeta) -> Type:
        cls._plugins[meta.name] = plugin_class
        cls._meta[meta.name] = meta
        return plugin_class

    @classmethod
    def get(cls, name: str) -> Optional[Any]:
        return cls._plugins.get(name)

    @classmethod
    def get_all(cls, plugin_type: Optional[PluginType] = None) -> Dict[str, Any]:
        if plugin_type is None:
            return dict(cls._plugins)
        return {
            name: cls._plugins[name]
            for name, meta in cls._meta.items()
            if meta.plugin_type == plugin_type
        }

    @classmethod
    def get_by_category(cls, category: str) -> Dict[str, Any]:
        return {
            name: cls._plugins[name]
            for name, meta in cls._meta.items()
            if meta.category == category
        }

    @classmethod
    def get_by_tag(cls, tag: str) -> Dict[str, Any]:
        return {
            name: cls._plugins[name]
            for name, meta in cls._meta.items()
            if tag in meta.tags
        }

    @classmethod
    def get_meta(cls, name: str) -> Optional[PluginMeta]:
        return cls._meta.get(name)

    @classmethod
    def list_plugins(cls, plugin_type: Optional[PluginType] = None) -> List[PluginMeta]:
        if plugin_type is None:
            return list(cls._meta.values())
        return [m for m in cls._meta.values() if m.plugin_type == plugin_type]

    @classmethod
    def hook(cls, event: str):
        def decorator(func: Callable):
            if event not in cls._hooks:
                cls._hooks[event] = []
            cls._hooks[event].append(func)
            return func
        return decorator

    @classmethod
    def trigger_hook(cls, event: str, *args, **kwargs):
        for handler in cls._hooks.get(event, []):
            try:
                handler(*args, **kwargs)
            except Exception:
                pass

    @classmethod
    def clear(cls):
        cls._plugins.clear()
        cls._meta.clear()
        cls._hooks.clear()


registry = PluginRegistry()
