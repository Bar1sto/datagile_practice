from uuid import UUID
from fastapi import (
    APIRouter,
    Depends,
    Query,
    HTTPException,
)
from app.api.errors import error_detail
from app.clients.nvd import NvdClient
from app.core.config import Settings
from app.schemas.error import ErrorResponse
from app.schemas.sync import (
    SyncRunPaginatedResponse,
    SyncRunResponse,
    SyncResultResponse,
)
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.repositories.sync import (
    list_sync_runs,
    count_sync_runs,
    get_sync_run_id,
    mark_sync_run_failed,
    create_sync_run,
)
from app.services.nvd_sync import NvdSyncService

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


@router.post("/nvd/recent", response_model=SyncResultResponse)
def post_sync_run(
    db: Session = Depends(get_db),
    days: int = Query(default=1, ge=1, le=7),
):
    settings = Settings()
    nvd_client = NvdClient(
        api_key=settings.nvd_api_key,
        base_url=settings.nvd_base_url,
        timeout_seconds=settings.nvd_timeout_seconds,
        max_retries=settings.nvd_max_retries,
        retry_sleep_seconds=settings.nvd_retry_sleep_seconds,
        results_per_page=settings.nvd_results_per_page,
    )
    nvd_sync_service = NvdSyncService(
        client=nvd_client,
        initial_load_months=settings.nvd_initial_load_months,
        chunk_days=settings.nvd_chunk_days,
    )
    try:
        result = nvd_sync_service.sync_recent(db=db, days=days)
        db.commit()
        return SyncResultResponse(
            total_count=result.total_count,
            added_count=result.added_count,
            updated_count=result.updated_count,
        )
    except Exception:
        db.rollback()
        sync_run = create_sync_run(db=db, source="NVD")
        mark_sync_run_failed(sync_run)
        db.commit()
        raise
