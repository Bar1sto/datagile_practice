from datetime import datetime
from dataclasses import dataclass
from typing import Literal, Any
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.models.cve import CveRecord, CveAffectedProduct


@dataclass
class CveUpsertAsyncResult:
    record: CveRecord
    created: bool


async def get_by_cve_id_async(
    db: AsyncSession,
    cve_id: str,
) -> CveRecord | None:
    statement = (
        select(CveRecord)
        .options(selectinload(CveRecord.affected_products))
        .where(CveRecord.cve_id == cve_id)
    )
    result = await db.execute(statement)
    return result.scalar_one_or_none()


async def list_cves_async(
    db: AsyncSession,
    limit: int,
    offset: int,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
    published_from: datetime | None,
    published_to: datetime | None,
    vendor: str | None,
    product: str | None,
) -> list[CveRecord]:
    statement = select(CveRecord)
    if severity is not None:
        statement = statement.where(CveRecord.cvss_base_severity == severity)

    if published_from is not None:
        statement = statement.where(CveRecord.published_at >= published_from)

    if published_to is not None:
        statement = statement.where(CveRecord.published_at <= published_to)

    if vendor is not None or product is not None:
        statement = statement.join(CveAffectedProduct).distinct()

    if vendor is not None:
        statement = statement.where(CveAffectedProduct.vendor.ilike(f"%{vendor}%"))

    if product is not None:
        statement = statement.where(CveAffectedProduct.product.ilike(f"%{product}%"))

    statement = (
        statement.order_by(CveRecord.published_at.desc(), CveRecord.cve_id.asc())
        .offset(offset)
        .limit(limit)
    )

    result = await db.execute(statement)
    return list(result.scalars().all())


async def count_cves_async(
    db: AsyncSession,
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
    published_from: datetime | None,
    published_to: datetime | None,
    vendor: str | None,
    product: str | None,
) -> int:
    if vendor is not None or product is not None:
        statement = (
            select(func.count(CveRecord.id.distinct()))
            .select_from(CveRecord)
            .join(CveAffectedProduct)
        )
    else:
        statement = select(func.count()).select_from(CveRecord)

    if severity is not None:
        statement = statement.where(CveRecord.cvss_base_severity == severity)

    if published_from is not None:
        statement = statement.where(CveRecord.published_at >= published_from)

    if published_to is not None:
        statement = statement.where(CveRecord.published_at <= published_to)

    if vendor is not None:
        statement = statement.where(CveAffectedProduct.vendor.ilike(f"%{vendor}%"))
    if product is not None:
        statement = statement.where(CveAffectedProduct.product.ilike(f"%{product}%"))

    result = await db.execute(statement)
    return result.scalar_one()


def replace_affected_products_async(
    record: CveRecord,
    affected_products_data: list[dict[str, Any]],
) -> None:
    record.affected_products.clear()

    for affected_product_data in affected_products_data:
        if not isinstance(affected_product_data, dict):
            continue

        vendor = affected_product_data.get("vendor")
        product = affected_product_data.get("product")
        cpe_uri = affected_product_data.get("cpe_uri")
        version = affected_product_data.get("version")

        if vendor is None or product is None:
            continue

        affected_product = CveAffectedProduct(
            vendor=vendor,
            product=product,
            cpe_uri=cpe_uri,
            version=version,
        )
        record.affected_products.append(affected_product)


async def upsert_cve_async(
    db: AsyncSession, cve_data: dict[str, Any]
) -> CveUpsertAsyncResult:
    cve_id = cve_data["cve_id"]
    cve_record_data = cve_data.copy()
    affected_products_data = cve_record_data.pop("affected_products", [])
    existing = await get_by_cve_id_async(
        db=db,
        cve_id=cve_id,
    )
    if existing is None:
        obj = CveRecord(**cve_record_data)
        db.add(obj)
        replace_affected_products_async(
            record=obj,
            affected_products_data=affected_products_data,
        )
        return CveUpsertAsyncResult(record=obj, created=True)
    for key, value in cve_record_data.items():
        if key == "source_identifier" and existing.source_identifier:
            continue
        if value is None:
            continue
        if value == "":
            continue
        setattr(existing, key, value)
    if affected_products_data:
        replace_affected_products_async(
            record=existing,
            affected_products_data=affected_products_data,
        )
    return CveUpsertAsyncResult(record=existing, created=False)
