from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    status_code = exc.status_code
    if isinstance(detail, dict) and "error" in detail:
        content = detail
    else:
        content = {"error": {"code": "HTTP_ERROR", "message": str(detail)}}
    return JSONResponse(content=content, status_code=status_code)
