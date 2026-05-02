import traceback
from fastapi import Request
from fastapi.responses import JSONResponse
from app.utils.logger import get_logger

logger = get_logger("middleware")


async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {request.method} {request.url} -> {exc}")
    logger.debug(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "InternalServerError",
            "message": str(exc),
            "path": str(request.url),
        },
    )
