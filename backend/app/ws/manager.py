import asyncio
import json
from datetime import datetime
from typing import Dict, Set
from fastapi import WebSocket
from app.utils.logger import get_logger

logger = get_logger("ws_manager")


class ConnectionManager:
    def __init__(self):
        self._active: Dict[str, Set[WebSocket]] = {}
        self._global: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, task_id: str | None = None):
        await websocket.accept()
        async with self._lock:
            if task_id:
                if task_id not in self._active:
                    self._active[task_id] = set()
                self._active[task_id].add(websocket)
                logger.info(f"WS connected to task {task_id}, total: {len(self._active[task_id])}")
            else:
                self._global.add(websocket)
                logger.info(f"WS global connected, total: {len(self._global)}")

    async def disconnect(self, websocket: WebSocket, task_id: str | None = None):
        async with self._lock:
            if task_id and task_id in self._active:
                self._active[task_id].discard(websocket)
                if not self._active[task_id]:
                    del self._active[task_id]
            else:
                self._global.discard(websocket)

    async def broadcast_task(self, task_id: str, event: str, data: dict):
        message = json.dumps({
            "event": event,
            "task_id": task_id,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }, ensure_ascii=False)

        targets = set()
        async with self._lock:
            if task_id in self._active:
                targets.update(self._active[task_id])
            targets.update(self._global)

        dead = set()
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    for task_set in self._active.values():
                        task_set.discard(ws)
                    self._global.discard(ws)

    async def broadcast_global(self, event: str, data: dict):
        message = json.dumps({
            "event": event,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }, ensure_ascii=False)

        async with self._lock:
            targets = self._global.copy()

        dead = set()
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._global.discard(ws)

    @property
    def total_connections(self) -> int:
        return len(self._global) + sum(len(s) for s in self._active.values())


ws_manager = ConnectionManager()
