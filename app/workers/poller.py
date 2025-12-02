from __future__ import annotations

import os
import socket
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Tuple, Optional, Set, TypeVar
import time
from typing import Dict
from collections import defaultdict

from dotenv import load_dotenv

load_dotenv()

from db.session import SessionLocal
from db.actions.ip_list import get_ip_list_after_id
from db.actions.checked_ips import get_node_if_exists, upsert_checked_ip
from db.models import IpList, CheckedIp
from db.actions.scanned_ips import add_scan_from_iplist_row


BATCH_SIZE = int(os.getenv("POLL_BATCH_SIZE", "100"))
MAX_FETCH = int(os.getenv("POLL_MAX_FETCH", "5000"))
MAX_WORKERS = int(os.getenv("POLL_MAX_WORKERS", "16"))
STATE_FILE = os.getenv("POLL_STATE_FILE", "state/last_ip_list_id.txt")
CONNECT_TIMEOUT = float(os.getenv("POLL_CONNECT_TIMEOUT", "2.0"))
STALE_AFTER = int(os.getenv("POLL_STALE_AFTER_HOURS", "2"))

T = TypeVar("T")

def map_targets_to_rows(rows: list[IpList]) -> Dict[Tuple[str, int], List[IpList]]:
    m: Dict[Tuple[str, int], List[IpList]] = defaultdict(list)
    for r in rows:
        if r.destination_ip and r.destination_port:
            key = (str(r.destination_ip), int(r.destination_port))
            m[key].append(r)
    return dict(m)

def _ensure_state_dir(path: str) -> None:
    p = Path(path).expanduser()
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)

def load_last_id(path: str) -> int:
    p = Path(path).expanduser()
    try:
        return int(p.read_text().strip())
    except Exception:
        return 0

def save_last_id(path: str, last_id: int) -> None:
    _ensure_state_dir(path)
    Path(path).expanduser().write_text(str(last_id))


def tcp_connect_ok(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def needs_probe(existing: Optional[CheckedIp], stale_after_hours: int) -> bool:
    if existing is None or existing.timestamp is None:
        return True
    now = datetime.now(timezone.utc)
    return existing.timestamp < (now - timedelta(hours=stale_after_hours))

def process_item(ip: str, port: int, row_ctx: IpList) -> Tuple[str, int, bool]:
    with SessionLocal() as db:
        existing = get_node_if_exists(db, ip=ip, port=port)
        now = datetime.now(timezone.utc)

        # existing and fresh → no probe, record cache=True
        if existing and not needs_probe(existing, STALE_AFTER):
            status = existing.status
            add_scan_from_iplist_row(db, row=row_ctx, status=status, scan_timestamp=now, cache=True)
            db.commit()
            return (ip, port, status == "active")

        # new or stale → probe
        ok = tcp_connect_ok(ip, port, CONNECT_TIMEOUT)
        status = "active" if ok else "inactive"

        # update checked_ips timestamp
        upsert_checked_ip(db, ip=ip, port=port, status=status, timestamp=now)

        # record scan event (cache=False since probe was done)
        add_scan_from_iplist_row(db, row=row_ctx, status=status, scan_timestamp=now, cache=False)

        db.commit()
        return (ip, port, ok)



def chunked(items: Iterable[T], size: int) -> Iterable[List[T]]:
    seq = list(items)  
    for i in range(0, len(seq), size):
        yield seq[i:i + size]

def unique_ip_port(rows: List[IpList]) -> List[Tuple[str, int]]:
    """Extract unique (destination_ip, destination_port) pairs, ignoring nulls."""
    seen: Set[Tuple[str, int]] = set()
    out: List[Tuple[str, int]] = []
    for r in rows:
        if r.destination_ip and r.destination_port:
            key = (str(r.destination_ip), int(r.destination_port))
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def poll_once() -> None:
    last_id = load_last_id(STATE_FILE)

    # Fetch new ip_list entries
    with SessionLocal() as db:
        rows = get_ip_list_after_id(db, last_id=last_id, limit=MAX_FETCH)

    if not rows:
        print(f"[poll] No new ip_list rows after id={last_id}")
        return

    new_max_id = max(r.id for r in rows)

    targets_map = map_targets_to_rows(rows)
    unique_targets = len(targets_map)
    total_entries = sum(len(v) for v in targets_map.values())

    jobs: List[Tuple[str, int, IpList]] = [
        (ip, port, row)
        for (ip, port), row_list in targets_map.items()
        for row in row_list
    ]

    print(
        f"[poll] Got {len(rows)} ip_list rows → {unique_targets} unique targets, "
        f"{total_entries} total entries. Batch {BATCH_SIZE}, workers {MAX_WORKERS}"
    )

    total_ok = 0
    total_fail = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for jobs_batch in chunked(jobs, BATCH_SIZE):
            futures = [pool.submit(process_item, ip, port, row_ctx)
                       for (ip, port, row_ctx) in jobs_batch]

            for fut in as_completed(futures):
                try:
                    ip, port, ok = fut.result()
                    if ok:
                        total_ok += 1
                    else:
                        total_fail += 1
                except Exception as e:
                    total_fail += 1
                    print(f"[poll] worker error: {e}")

    print(
        f"[poll] Done. Reachable: {total_ok}, Unreachable: {total_fail}. "
        f"Updating last_id → {new_max_id}"
    )
    save_last_id(STATE_FILE, new_max_id)

def main():
    interval = int(os.getenv("POLL_INTERVAL_SECONDS", "20")) 

    print(f"[poller] Starting continuous polling every {interval} seconds…")

    try:
        while True:
            start = time.time()
            poll_once()
            elapsed = time.time() - start
            # sleep for remaining time, never less than 0
            to_sleep = max(0, interval - elapsed)
            if to_sleep:
                print(f"[poller] Sleeping {to_sleep:.1f}s before next cycle…")
                time.sleep(to_sleep)
    except KeyboardInterrupt:
        print("\n[poller] Stopped by user.")

if __name__ == "__main__":
    main()