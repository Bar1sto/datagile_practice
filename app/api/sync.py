from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Query,
    HTTPException,
    Path,
)

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import error_detail
from app.clients.nvd import AsyncNvdClient
from app.clients.osv import OsvClient
from app.core.config import Settings

from app.db.database import get_async_db

from app.schemas.error import ErrorResponse
from app.schemas.osv import OsvPackageSyncRequest, OsvPackageSyncQueryResponse
from app.schemas.sync import (
    SyncRunPaginatedResponse,
    SyncRunResponse,
    SyncResultResponse,
)

from app.repositories.sync import (
    count_sync_runs_async,
    get_sync_run_id_async,
    list_sync_runs_async,
)

from app.services.nvd_sync import AsyncNvdSyncService
from app.services.osv_sync import OsvSyncService


router = APIRouter(
    prefix="/sync-runs",
    tags=["sync-runs"],
)


def build_async_nvd_service() -> AsyncNvdSyncService:
    settings = Settings()
    nvd_client = AsyncNvdClient(
        api_key=settings.nvd_api_key,
        base_url=settings.nvd_base_url,
        timeout_seconds=settings.nvd_timeout_seconds,
        max_retries=settings.nvd_max_retries,
        retry_sleep_seconds=settings.nvd_retry_sleep_seconds,
        results_per_page=settings.nvd_results_per_page,
    )
    return AsyncNvdSyncService(
        client=nvd_client,
        initial_load_months=settings.nvd_initial_load_months,
        chunk_days=settings.nvd_chunk_days,
    )


@router.get(
    "/",
    response_model=SyncRunPaginatedResponse,
    summary="List sync runs",
    description=(
        "Returns paginated synchronization history for vulnerability sources "
        "such as NVD and OSV"
    ),
)
async def list_sync_run_history(
    db: AsyncSession = Depends(get_async_db),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of sync runs to skip before returning results",
        example=0,
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of sync runs to return",
        example=20,
    ),
) -> SyncRunPaginatedResponse:
    sync_records = await list_sync_runs_async(
        db=db,
        offset=offset,
        limit=limit,
    )
    items = [
        SyncRunResponse.model_validate(sync_record) for sync_record in sync_records
    ]
    total = await count_sync_runs_async(
        db=db,
    )
    return SyncRunPaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{sync_run_id}",
    response_model=SyncRunResponse,
    summary="Get sync run details",
    description=(
        "Returns details for a single synchronization run, including source, "
        "status, processed counts, start time and finish time"
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "sync_run not found",
        }
    },
)
async def get_sync_run_detail(
    sync_run_id: UUID = Path(
        ...,
        description="Unique identifier of the sync run",
        example="550e8400-e29b-41d4-a716-446655440000",
    ),
    db: AsyncSession = Depends(get_async_db),
) -> SyncRunResponse:
    sync_run = await get_sync_run_id_async(
        db=db,
        sync_run_id=sync_run_id,
    )
    if sync_run is None:
        raise HTTPException(
            status_code=404,
            detail=error_detail("SYNC_RUN_NOT_FOUND", "sync_run_id not found"),
        )
    return SyncRunResponse.model_validate(sync_run)


@router.post(
    "/nvd/recent",
    response_model=SyncResultResponse,
    summary="Run recent NVD synchronization",
    description=(
        "Start a manual synchronization with the NVD API for recently modified "
        "CVEs. The endpoint fetches CVEs from the last selected number of days, "
        "upserts them into the database and creates a sync run record"
    ),
)
async def run_recent_nvd_sync(
    db: AsyncSession = Depends(get_async_db),
    days: int = Query(
        default=1,
        ge=1,
        le=7,
        description="Number of recent days to synchronize from NVD",
        example=1,
    ),
) -> SyncResultResponse:
    nvd_sync_service = build_async_nvd_service()
    result = await nvd_sync_service.sync_recent(db=db, days=days)
    return SyncResultResponse(
        total_count=result.total_count,
        added_count=result.added_count,
        updated_count=result.updated_count,
    )


@router.post(
    "/osv/package",
    response_model=OsvPackageSyncQueryResponse,
    summary="Run OSV package synchronization",
    description=(
        "Queries OSV vulnerabilities for a specific package ecosystem, package "
        "name and version. Only vulnerabilities with CVE aliases are stored. "
        "Duplicate CVE aliases within the OSV response are skipped."
    ),
)
async def run_osv_package_sync(
    request: OsvPackageSyncRequest, db: AsyncSession = Depends(get_async_db)
) -> OsvPackageSyncQueryResponse:
    settings = Settings()
    client = OsvClient(
        base_url=settings.osv_base_url,
        timeout_seconds=settings.osv_timeout_seconds,
    )
    service = OsvSyncService(client=client)
    result = await service.sync_package(
        db=db,
        ecosystem=request.ecosystem,
        package_name=request.package_name,
        version=request.version,
    )
    return OsvPackageSyncQueryResponse(
        total_count=result.total_count,
        added_count=result.added_count,
        updated_count=result.updated_count,
        skipped_count=result.skipped_count,
    )


@router.post(
    "/nvd/initial-load",
    response_model=SyncResultResponse,
    summary="Run initial NVD load",
    description=(
        "Starts a manual initial load from the NVD API for the selected number "
        "of past months. By default, it loads CVEs from the last 12 months and "
        "creates a sync run record"
    ),
)
async def run_initial_nvd_load(
    months: int = Query(
        default=12,
        ge=1,
        le=12,
        description="Number of past months to synchronize from NVD",
        example=12,
    ),
    db: AsyncSession = Depends(get_async_db),
) -> SyncResultResponse:
    nvd_sync_service = build_async_nvd_service()
    result = await nvd_sync_service.sync_initial_load(db=db, months=months)
    return SyncResultResponse(
        total_count=result.total_count,
        added_count=result.added_count,
        updated_count=result.updated_count,
    )
