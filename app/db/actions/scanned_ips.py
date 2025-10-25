from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert
from ..models import IpList


from ..models import ScannedIp

def add_scanned_ip(
    db: Session,
    *,
    source_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    network: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: Optional[int] = None,
    last_seen: Optional[datetime] = None,
    services: Optional[int] = None,
    services_decoded: Optional[str] = None,
    status: str = "unknown",
    cache: bool = False,
    timestamp: Optional[datetime] = None,
    scan_timestamp: Optional[datetime] = None,
) -> ScannedIp:
    """
    Insert a new scanned_ips row. timestamp/scan_timestamp default to NOW() UTC if not given.
    """
    now = datetime.now(timezone.utc)
    row = ScannedIp(
        timestamp=timestamp or now,
        source_ip=source_ip,
        source_port=source_port,
        network=network,
        destination_ip=destination_ip,
        destination_port=destination_port,
        last_seen=last_seen,
        services=services,
        services_decoded=services_decoded,
        status=status,
        scan_timestamp=scan_timestamp or now,
        cache=cache,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row

def get_scanned_ips_after_id(db: Session, last_id: int, limit: int = 1000) -> List[ScannedIp]:
    """
    Fetch rows with id > last_id in ascending id order.
    """
    stmt = (
        select(ScannedIp)
        .where(ScannedIp.id > last_id)
        .order_by(ScannedIp.id.asc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars())

def get_scanned_ips_by_status(
    db: Session, status: str = "active"
) -> List[ScannedIp]:
    """
    Fetch rows by status (e.g., 'active', 'inactive', 'unknown'), newest first by scan_timestamp.
    """
    stmt = (
        select(ScannedIp)
        .where(ScannedIp.status == status)
        .order_by(ScannedIp.id.asc())
    )
    return list(db.execute(stmt).scalars())

def bulk_add_scanned_ips(
    db: Session,
    rows: Sequence[Mapping],
    *,
    chunk_size: int = 1000,
) -> List[ScannedIp]:
    if not rows:
        return []

    now = datetime.now(timezone.utc)
    prepared = []
    for r in rows:
        prepared.append({
            "timestamp": r.get("timestamp", now),
            "source_ip": r.get("source_ip"),
            "source_port": r.get("source_port"),
            "network": r.get("network"),
            "destination_ip": r.get("destination_ip"),
            "destination_port": r.get("destination_port"),
            "last_seen": r.get("last_seen"),
            "services": r.get("services"),
            "services_decoded": r.get("services_decoded"),
            "status": r.get("status", "unknown"),
            "scan_timestamp": r.get("scan_timestamp", now),
            "cache": r.get("cache", False),
        })

    inserted: List[ScannedIp] = []
    for i in range(0, len(prepared), chunk_size):
        chunk = prepared[i:i + chunk_size]
        stmt = pg_insert(ScannedIp).values(chunk).returning(ScannedIp)
        inserted.extend(db.execute(stmt).scalars().all())

    db.commit()
    return inserted


def add_scan_from_iplist_row(
    db: Session,
    *,
    row: IpList,
    status: str,
    scan_timestamp: datetime | None = None,
    cache: bool = False,
):
    """
    Create a scanned_ips record using fields copied from an IpList row.
    If cache=True, it means no new network scan was performed (used cached info).
    """
    now = scan_timestamp or datetime.now(timezone.utc)
    return add_scanned_ip(
        db,
        timestamp=row.timestamp,
        source_ip=row.source_ip,
        source_port=row.source_port,
        network=row.network,
        destination_ip=row.destination_ip,
        destination_port=row.destination_port,
        last_seen=row.last_seen,
        services=row.services,
        services_decoded=row.services_decoded,
        status=status,
        scan_timestamp=now,
        cache=cache,
    )