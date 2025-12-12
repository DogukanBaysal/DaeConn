from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, Text, UniqueConstraint, Index, func, Boolean
from sqlalchemy.dialects.postgresql import BIGINT, INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class CheckedIp(Base):
    __tablename__ = "checked_ips"

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_handshake: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,       
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="unknown")

    __table_args__ = (
        UniqueConstraint("ip", "port", name="checked_ips_ip_port_uniq"),
        Index("idx_checked_ips_timestamp", "timestamp"),
        Index("idx_checked_ips_status", "status"),
    )

class IpList(Base):
    __tablename__ = "ip_list"

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        "timestamp", DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source_ip: Mapped[Optional[str]] = mapped_column(INET)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    network: Mapped[Optional[str]] = mapped_column(Text)
    destination_ip: Mapped[Optional[str]] = mapped_column(INET)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    services: Mapped[Optional[int]] = mapped_column(BIGINT)
    services_decoded: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("idx_ip_list_id", "id"),
        Index("idx_ip_list_timestamp", "timestamp"),
        Index("idx_ip_list_destination_ip", "destination_ip"),
    )


class ScannedIp(Base):
    __tablename__ = "scanned_ips"

    id: Mapped[int] = mapped_column(BIGINT, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        "timestamp", DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source_ip: Mapped[Optional[str]] = mapped_column(INET)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    network: Mapped[Optional[str]] = mapped_column(Text)
    destination_ip: Mapped[Optional[str]] = mapped_column(INET)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    services: Mapped[Optional[int]] = mapped_column(BIGINT)
    services_decoded: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="unknown")
    scan_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    cache: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    __table_args__ = (
        # helpful indexes for common lookups
        Index("idx_scanned_ips_id", "id"),
        Index("idx_scanned_ips_timestamp", "timestamp"),
        Index("idx_scanned_ips_destination_ip", "destination_ip"),
        Index("idx_scanned_ips_status", "status"),
        Index("idx_scanned_ips_scan_timestamp", "scan_timestamp"),
    )