# app/workers/peer_scanner.py
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterable, List, Tuple, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
from datetime import datetime, timezone

from dotenv import load_dotenv

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.session import SessionLocal
from db.actions.checked_ips import get_active_checked_ips, set_last_handshake, is_checked_within_hours, upsert_checked_ip
from db.models import IpList

from network.scanner import scan_peer
import logging
import os
import threading
import csv


load_dotenv()

LOG_LEVEL = os.getenv("SCAN_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s")
logger = logging.getLogger("scanner")
ACTIVE_IPS_CSV = os.getenv("ACTIVE_IPS_CSV", "exports/active_checked_ips.csv")

MAX_AGE_HOURS = int(os.getenv("MAX_AGE_HOURS", 1))

IPS_FILE = os.getenv("SCAN_IPS_FILE", "state/peers.txt")
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "60"))

CHECKED_ACTIVE_LIMIT = int(os.getenv("SCAN_CHECKED_ACTIVE_LIMIT", "1000"))

MAX_WORKERS = int(os.getenv("SCAN_MAX_WORKERS", "64"))
BATCH_SIZE = int(os.getenv("SCAN_BATCH_SIZE", "12"))  

INSERT_CHUNK_SIZE = int(os.getenv("SCAN_INSERT_CHUNK_SIZE", "1000"))

MIN_BIGINT = -2**63
MAX_BIGINT = 2**63 - 1

def to_signed_bigint_from_uint64(x: int) -> int:
    """
    Convert a uint64 (0..2^64-1) to a signed 64-bit integer (-2^63..2^63-1),
    which is what Postgres BIGINT expects.
    """
    if x is None:
        return None
    if x < 0:
        # already negative, probably not a uint64
        return x
    if x <= MAX_BIGINT:
        return x
    # map uint64 to signed representation
    return x - 2**64

def parse_ip_port_line(line: str) -> Optional[Tuple[str, int]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if ":" not in line:
        return None
    ip, port = line.rsplit(":", 1)
    try:
        # basic validation + normalize
        ip_address(ip)
        port_i = int(port)
        if not (1 <= port_i <= 65535):
            return None
        return (ip, port_i)
    except Exception:
        return None


def read_ips_file(path: str) -> List[Tuple[str, int]]:
    p = Path(path).expanduser()
    if not p.exists():
        return []
    out: List[Tuple[str, int]] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        t = parse_ip_port_line(raw)
        if t:
            out.append(t)
    return out


def chunked(items: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def unique_targets_from_file_and_db(db: Session) -> List[Tuple[str, int]]:
    active_rows = get_active_checked_ips(db, limit=CHECKED_ACTIVE_LIMIT)
    db_targets = [(str(r.ip), int(r.port)) for r in active_rows if r.ip and r.port]

    seen: set[Tuple[str, int]] = set()
    merged: List[Tuple[str, int]] = []
    for lst in (db_targets, ):
        for t in lst:
            if t not in seen:
                seen.add(t)
                merged.append(t)

    return merged



def _parse_time_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    ts_dt: Optional[datetime] = None
    if "time" in item and item["time"]:
        try:
            ts_dt = datetime.fromisoformat(str(item["time"]))
            if ts_dt.tzinfo is None:
                ts_dt = ts_dt.replace(tzinfo=timezone.utc)
        except Exception:
            ts_dt = None

    if ts_dt is None and "timestamp" in item and item["timestamp"] is not None:
        try:
            ts_dt = datetime.fromtimestamp(int(item["timestamp"]), tz=timezone.utc)
        except Exception:
            ts_dt = None

    # last_seen can be epoch
    ls_dt: Optional[datetime] = None
    if "last_seen" in item and item["last_seen"] is not None:
        try:
            ls_dt = datetime.fromtimestamp(int(item["last_seen"]), tz=timezone.utc)
        except Exception:
            ls_dt = None

    return {"timestamp": ts_dt, "last_seen": ls_dt}


def _services_decoded_to_text(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, (list, tuple)):
        return ",".join(map(str, val))
    return str(val)


def normalize_scan_result(item: Dict[str, Any]) -> Dict[str, Any]:
    times = _parse_time_fields(item)
    return {
        "timestamp": times["timestamp"],
        "source_ip": item.get("source_ip"),
        "source_port": item.get("source_port"),
        "network": item.get("network"),
        "destination_ip": item.get("destination_ip"),
        "destination_port": item.get("destination_port"),
        "last_seen": times["last_seen"],
        "services": to_signed_bigint_from_uint64(item.get("services")),
        "services_decoded": _services_decoded_to_text(item.get("services_decoded")),
    }



def bulk_insert_ip_list(db: Session, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    total = 0
    for chunk in chunked(rows, INSERT_CHUNK_SIZE):
        stmt = pg_insert(IpList).values(chunk).returning(IpList.id)
        total += len(db.execute(stmt).scalars().all())
    db.commit()
    return total


def scan_one_peer(ip: str, port: int) -> list[dict]:
    try:
        out = scan_peer(ip, port)
    except Exception as e:
        logger.exception("scan_peer raised for %s:%s", ip, port)
        return []
    if not out:
        logger.debug("%s:%s -> no data", ip, port)
        return []
    if isinstance(out, list):
        # logger.info("%s:%s -> scanned, returned %d item(s)", ip, port, len(out))
        return out
    # logger.info("%s:%s -> scanned, returned single item", ip, port)
    return [out]

def process_batch(targets: list[tuple[str, int]]) -> list[dict]:
    results: list[dict] = []
    response = []
    # logger.info("Processing batch of %d targets", len(targets))
    for ip, port in targets:
        results_from_peer = scan_one_peer(ip, port)
        for r in results_from_peer:
            dst = r.get("destination_ip"), r.get("destination_port")
            # logger.debug("-> decoded from %s:%s -> dest=%s last_seen=%s services=%s",
            #              ip, port, dst, r.get("last_seen"), r.get("services_decoded"))
        if len(results_from_peer) == 0:
            response.append((ip, port, "invalid"))
        else:
            response.append((ip, port, "valid"))
        results.extend(results_from_peer)
    # logger.info("Finished batch: got %d results", len(results))
    return results, response


def _worker_scan_and_insert(t_batch: List[Any]) -> Tuple[int, int]:
    thread_name = threading.current_thread().name
    # logger.info("[%s] worker starting batch of %d targets", thread_name, len(t_batch))
    try:
        batch_res, response_list = process_batch(t_batch) or [], []
    except Exception as e:
        logger.exception("process_batch error")
        return (0, 0)

    if not batch_res:
        logger.info("[%s] no results from scan", thread_name)
        return (0, 0)

    to_insert = [normalize_scan_result(x) for x in batch_res]
    to_insert = [r for r in to_insert
                 if r.get("destination_ip") and r.get("destination_port")]

    if not to_insert:
        logger.info("[%s] no valid insertable rows after normalization", thread_name)
        return (0, 0)

    try:
        with SessionLocal() as db:
            inserted = bulk_insert_ip_list(db, to_insert)
            # logger.info("[%s] inserted %d/%d rows", thread_name, inserted, len(to_insert))
            return (inserted, len(to_insert), response_list)
    except Exception as e:
        logger.exception("DB error in worker (attempted=%d)", len(to_insert))
        return (0, len(to_insert))


def export_active_checked_ips_to_csv() -> None:
    export_time = datetime.now(timezone.utc).isoformat()

    with SessionLocal() as db:
        rows = get_active_checked_ips(db, limit=CHECKED_ACTIVE_LIMIT)

    if not rows:
        logger.info("[active-export] No active checked IPs to export.")
        return

    path = Path(ACTIVE_IPS_CSV)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_exists = path.exists()

    # append mode
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write header only if file does not exist
        if not file_exists:
            writer.writerow([
                "export_time",
                "ip",
                "port",
                "status",
                "timestamp"
            ])

        # Append rows
        for r in rows:
            ip = str(getattr(r, "ip", None))
            port = getattr(r, "port", None)
            status = getattr(r, "status", None)
            ts = getattr(r, "timestamp", None)
            ts_str = ts.isoformat() if ts is not None else None

            writer.writerow([
                export_time,
                ip,
                port,
                status,
                ts_str,
            ])

    logger.info("[active-export] Appended %d active IPs to %s", len(rows), path)


def scan_cycle() -> None:
    with SessionLocal() as db:
        all_targets = unique_targets_from_file_and_db(db)

        # keep only IPs that were NOT checked within the last MAX_AGE_HOURS
        targets = [
            (ip, port)
            for ip, port in all_targets
            if not is_checked_within_hours(db, ip, port, MAX_AGE_HOURS)
        ]

    if not targets:
        print("[scanner] No targets found (file + DB).")
        return

    print(f"[scanner] Cycle targets: {len(targets)} "
          f"(workers={MAX_WORKERS}, batch={BATCH_SIZE})")

    total_inserted = 0
    total_attempted = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = []
        for t_batch in chunked(targets, BATCH_SIZE):
            futures.append(pool.submit(_worker_scan_and_insert, t_batch))

        for fut in as_completed(futures):
            try:
                inserted, attempted, result_list = fut.result()
                total_inserted += inserted
                total_attempted += attempted
            except Exception as e:
                print(f"[scanner] worker future error: {e}")

    if total_attempted == 0:
        print("[scanner] No scan results to write.")
        return

    print(f"[scanner] Inserted {total_inserted}/{total_attempted} rows into ip_list.")
    
    export_active_checked_ips_to_csv()

    with SessionLocal() as db:
        for (ip, port, status) in result_list:
            if status == "valid":
                set_last_handshake(db, ip, port)



def main():
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        file_targets = read_ips_file(IPS_FILE)
        for (ip, port) in file_targets:
            upsert_checked_ip(db, ip=ip, port=port, status="active", timestamp=now)


    interval = SCAN_INTERVAL_SECONDS
    print(f"[scanner] Starting continuous scan every {interval}s "
          f"(workers={MAX_WORKERS}, batch={BATCH_SIZE})")
    try:
        while True:
            start = time.time()
            scan_cycle()
            elapsed = time.time() - start
            sleep_for = max(0.0, interval - elapsed)
            if sleep_for > 0:
                time.sleep(sleep_for)
    except KeyboardInterrupt:
        print("\n[scanner] Stopped by user.")


if __name__ == "__main__":
    main()