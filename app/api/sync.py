from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException

from app.api.errors import error_detail
from app.schemas.error import ErrorResponse
from app.schemas.sync import SyncRunPaginatedResponse, SyncRunResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.repositories.sync import list_sync_runs, count_sync_runs, get_sync_run_id


router = APIRouter(
    prefix="/sync-runs",
    tags=["sync-runs"],
)


@router.get(
    "/",
    response_model=SyncRunPaginatedResponse,
)
def get_sync(
    db: Session = Depends(get_db),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
) -> SyncRunPaginatedResponse:
    sync_records = list_sync_runs(db=db, offset=offset, limit=limit)
    items = [
        SyncRunResponse.model_validate(sync_record) for sync_record in sync_records
    ]
    return SyncRunPaginatedResponse(
        items=items,
        total=count_sync_runs(db=db),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{sync_run_id}",
    response_model=SyncRunResponse,
    responses={
        404: {
            "model": ErrorResponse,
            "description": "sync_run not found",
        }
    },
)
def get_sync_run_detail(
    sync_run_id: UUID,
    db: Session = Depends(get_db),
) -> SyncRunResponse:
    sync_run = get_sync_run_id(db=db, sync_run_id=sync_run_id)
    if sync_run is None:
        raise HTTPException(
            status_code=404,
            detail=error_detail("SYNC_RUN_NOT_FOUND", "sync_run_id not found"),
        )
    return SyncRunResponse.model_validate(sync_run)
