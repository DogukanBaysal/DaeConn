from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, update, or_
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..models import CheckedIp


def get_all_checked_ips(
    db: Session,
    offset: int = 0,
) -> List[CheckedIp]:
    """
    Return all rows from checked_ips, newest first by timestamp.
    """
    stmt = (
        select(CheckedIp)
        .order_by(CheckedIp.timestamp.desc())
        .offset(offset)
    )
    return list(db.execute(stmt).scalars())

def get_active_checked_ips(
    db: Session,
    limit: int = 99999999,
    stale_after_minutes: int = 60,
) -> List[CheckedIp]:
    """
    Return rows where:
      - status == 'active'
      - AND (last_handshake is NULL OR last_handshake older than now - stale_after_minutes)

    Newest first by timestamp.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=stale_after_minutes)

    stmt = (
        select(CheckedIp)
        .where(CheckedIp.status == "active")
        .where(
            or_(
                CheckedIp.last_handshake.is_(None),
                CheckedIp.last_handshake < cutoff,
            )
        )
        .order_by(CheckedIp.timestamp.desc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars())


def get_node_if_exists(db: Session, ip: str, port: int) -> Optional[datetime]:
    """
    Checks if a (ip, port) exists in checked_ips.
    If yes, returns to it.
    """
    from ..models import CheckedIp  

    stmt = select(CheckedIp).where(
        CheckedIp.ip == ip,
        CheckedIp.port == port
    )
    result = db.execute(stmt).scalar_one_or_none()
    return result

def add_checked_ip(
    db: Session,
    *,
    ip: str,
    port: int,
    status: str = "unknown",
) -> CheckedIp:
    """
    Insert a new checked_ip entry.
    timestamp defaults to NOW().
    """
    now = datetime.now(timezone.utc)
    row = CheckedIp(ip=ip, port=port, status=status, timestamp=now)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row

def update_checked_ip(
    db: Session,
    *,
    ip: str,
    port: int,
    status: Optional[str] = None,
    update_timestamp: bool = True,
) -> Optional[CheckedIp]:
    """
    Updates status and/or timestamp for existing (ip, port).
    Returns the updated row or None if not found.
    """
    now = datetime.now(timezone.utc)
    stmt = (
        update(CheckedIp)
        .where(CheckedIp.ip == ip, CheckedIp.port == port)
        .values(
            **(
                {
                    "status": status if status is not None else CheckedIp.status,
                    "timestamp": now if update_timestamp else CheckedIp.timestamp,
                }
            )
        )
        .returning(CheckedIp)
    )
    result = db.execute(stmt).scalar_one_or_none()
    if result:
        db.commit()
    return result



def upsert_checked_ip(
    db: Session,
    *,
    ip: str,
    port: int,
    status: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> CheckedIp:
    """
    Insert or update a checked_ip entry.
    - If (ip, port) does not exist: insert a new row.
    - If it exists: update its status and/or timestamp.
    Returns the upserted CheckedIp row.
    """
    insert_values = {"ip": ip, "port": port}
    if status is not None:
        insert_values["status"] = status
    if timestamp is not None:
        insert_values["timestamp"] = timestamp

    stmt = (
        pg_insert(CheckedIp)
        .values(**insert_values)
        .on_conflict_do_update(
            index_elements=["ip", "port"],
            set_={
                "status": (status if status is not None else CheckedIp.status),
                "timestamp": (
                    timestamp if timestamp is not None else CheckedIp.timestamp
                ),
            },
        )
        .returning(CheckedIp)
    )

    result = db.execute(stmt).scalar_one()
    db.commit()
    return result



def is_checked_within_hours(
    db: Session,
    ip: str,
    port: int,
    max_age_hours: float,
) -> bool:
    """
    Return True if (ip, port) exists in checked_ips AND
    its last_handshake is within the last `max_age_hours` hours.
    """
    stmt = select(CheckedIp).where(
        CheckedIp.ip == ip,
        CheckedIp.port == port
    )

    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        return False  # IP/port not in the table at all

    if row.last_handshake is None:
        return False  # no timestamp stored → treat as stale

    now = datetime.now(timezone.utc)
    age = now - row.last_handshake

    return age <= timedelta(hours=max_age_hours)


def set_last_handshake(
    db: Session,
    ip: str,
    port: int,
) -> CheckedIp | None:
    """
    Update the `last_handshake` timestamp to NOW() for (ip, port).
    Returns the updated row, or None if not found.
    """
    now = datetime.now(timezone.utc)

    stmt = (
        update(CheckedIp)
        .where(CheckedIp.ip == ip, CheckedIp.port == port)
        .values(last_handshake=now)
        .returning(CheckedIp)
    )

    result = db.execute(stmt).scalar_one_or_none()
    if result:
        db.commit()

    return result