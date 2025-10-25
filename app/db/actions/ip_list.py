from __future__ import annotations
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import IpList

def get_ip_list_after_id(db: Session, last_id: int, limit: int = 1000) -> List[IpList]:
    """
    Fetch rows with id > last_id, ascending by id.
    """
    stmt = (
        select(IpList)
        .where(IpList.id > last_id)
        .order_by(IpList.id.asc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars())

def get_ip_list_range(
    db: Session,
    start_id: Optional[int] = None,
    end_id: Optional[int] = None,
    limit: int = 5000,
) -> List[IpList]:
    """
    Flexible range query: [start_id, end_id] (inclusive bounds if provided),
    ordered by id ascending.
    """
    stmt = select(IpList)
    if start_id is not None:
        stmt = stmt.where(IpList.id >= start_id)
    if end_id is not None:
        stmt = stmt.where(IpList.id <= end_id)
    stmt = stmt.order_by(IpList.id.asc()).limit(limit)
    return list(db.execute(stmt).scalars())