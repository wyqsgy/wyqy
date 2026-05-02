from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.ws.manager import ws_manager
from app.utils.logger import get_logger

logger = get_logger("ws_api")

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/tasks/{task_id}")
async def ws_task(websocket: WebSocket, task_id: str):
    await ws_manager.connect(websocket, task_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"event":"pong"}')
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, task_id)


@router.websocket("/ws/global")
async def ws_global(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"event":"pong"}')
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
