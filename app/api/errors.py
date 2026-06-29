from typing import Any


def error_detail(code: str, message: str) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
        }
    }
