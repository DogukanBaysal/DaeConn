from __future__ import annotations

import os
import time
import csv
import traceback
from pathlib import Path
from typing import List, Dict, Any

from dotenv import load_dotenv

load_dotenv()

from db.session import SessionLocal
from db.actions.scanned_ips import get_scanned_ips_after_id
from db.models import ScannedIp


EXPORT_FILE = os.getenv("EXPORT_FILE", "app/exports/scanned_ips.csv")
EXPORT_STATE_FILE = os.getenv("EXPORT_STATE_FILE", "state/last_scanned_export_id.txt")
EXPORT_INTERVAL_SECONDS = int(os.getenv("EXPORT_INTERVAL_SECONDS", "20"))
EXPORT_FETCH_LIMIT = int(os.getenv("EXPORT_FETCH_LIMIT", "5000"))

RETRY_BASE_SECONDS = float(os.getenv("EXPORT_RETRY_BASE_SECONDS", "2"))
RETRY_MAX_SECONDS = float(os.getenv("EXPORT_RETRY_MAX_SECONDS", "60"))

CSV_FIELDS = [
    "id",
    "timestamp",
    "source_ip",
    "source_port",
    "network",
    "destination_ip",
    "destination_port",
    "last_seen",
    "services",
    "services_decoded",
    "status",
    "scan_timestamp",
    "cache",
]


def ensure_parent(path: str) -> None:
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
    ensure_parent(path)
    Path(path).expanduser().write_text(str(last_id))

def file_needs_header(path: str) -> bool:
    p = Path(path).expanduser()
    return (not p.exists()) or p.stat().st_size == 0

def dt2str(dt) -> str | None:
    return dt.isoformat() if dt is not None else None

def row_to_dict(r: ScannedIp) -> Dict[str, Any]:
    return {
        "id": r.id,
        "timestamp": dt2str(r.timestamp),
        "source_ip": str(r.source_ip) if r.source_ip is not None else None,
        "source_port": r.source_port,
        "network": r.network,
        "destination_ip": str(r.destination_ip) if r.destination_ip is not None else None,
        "destination_port": r.destination_port,
        "last_seen": dt2str(r.last_seen),
        "services": r.services,
        "services_decoded": r.services_decoded,
        "status": r.status,
        "scan_timestamp": dt2str(r.scan_timestamp),
        "cache": r.cache,
    }


def export_once() -> int:
    """
    Exports new scanned_ips rows after the last exported id.
    """
    try:
        last_id = load_last_id(EXPORT_STATE_FILE)

        with SessionLocal() as db:
            rows: List[ScannedIp] = get_scanned_ips_after_id(
                db, last_id=last_id, limit=EXPORT_FETCH_LIMIT
            )

        if not rows:
            print(f"[export] No new scanned_ips rows after id={last_id}")
            return 0

        new_max_id = max(r.id for r in rows)
        ensure_parent(EXPORT_FILE)

        need_header = file_needs_header(EXPORT_FILE)
        with open(Path(EXPORT_FILE).expanduser(), mode="a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            if need_header:
                writer.writeheader()
            for r in rows:
                writer.writerow(row_to_dict(r))

        save_last_id(EXPORT_STATE_FILE, new_max_id)
        print(f"[export] Wrote {len(rows)} rows → {EXPORT_FILE} (last_id={new_max_id})")
        return new_max_id

    except Exception as e:
        print(f"[export][ERROR] export_once failed: {e}")
        traceback.print_exc()
        return 0


def main():
    interval = EXPORT_INTERVAL_SECONDS
    print(f"[export] Starting continuous export every {interval}s → {EXPORT_FILE}")

    retry_sleep = RETRY_BASE_SECONDS

    try:
        while True:
            start = time.time()
            try:
                export_once()
                retry_sleep = RETRY_BASE_SECONDS

                elapsed = time.time() - start
                sleep_for = max(0.0, interval - elapsed)
                if sleep_for:
                    time.sleep(sleep_for)

            except Exception as e:
                print(f"[export][FATAL-LOOP-ERROR] {e}")
                traceback.print_exc()

                print(f"[export] Retrying in {retry_sleep:.1f}s ...")
                time.sleep(retry_sleep)
                retry_sleep = min(RETRY_MAX_SECONDS, retry_sleep * 2)

    except KeyboardInterrupt:
        print("\n[export] Stopped by user.")


if __name__ == "__main__":
    main()