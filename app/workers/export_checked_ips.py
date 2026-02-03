from __future__ import annotations

import os
import time
import csv
import traceback
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import select
from db.session import SessionLocal
from db.models import CheckedIp


EXPORT_FILE = os.getenv("EXPORT_CHECKED_FILE", "app/exports/checked_ips.csv")
EXPORT_INTERVAL_SECONDS = int(os.getenv("EXPORT_CHECKED_INTERVAL_SECONDS", "21600"))

RETRY_BASE_SECONDS = float(os.getenv("EXPORT_RETRY_BASE_SECONDS", "2"))
RETRY_MAX_SECONDS = float(os.getenv("EXPORT_RETRY_MAX_SECONDS", "60"))

EXPORT_STREAM_BATCH = int(os.getenv("EXPORT_CHECKED_STREAM_BATCH", "5000"))

CSV_FIELDS = [
    "export_timestamp",
    "id",
    "ip",
    "port",
    "status",
    "timestamp",
    "last_handshake",
    "network",
]


def ensure_parent(path: str) -> None:
    p = Path(path).expanduser()
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)


def file_needs_header(path: str) -> bool:
    p = Path(path).expanduser()
    return (not p.exists()) or p.stat().st_size == 0


def dt2str(dt) -> str | None:
    return dt.isoformat() if dt is not None else None


def row_to_dict(r: CheckedIp, export_ts: datetime) -> Dict[str, Any]:
    return {
        "export_timestamp": export_ts.isoformat(),
        "id": r.id,
        "ip": str(r.ip) if r.ip is not None else None,
        "port": r.port,
        "status": r.status,
        "timestamp": dt2str(getattr(r, "timestamp", None)),
        "last_handshake": dt2str(getattr(r, "last_handshake", None)),
        "network": getattr(r, "network", None),
    }


def export_once() -> int:
    """
    Append ALL checked_ips rows to CSV.
    """
    try:
        ensure_parent(EXPORT_FILE)
        export_ts = datetime.utcnow()

        wrote = 0
        skipped = 0

        with SessionLocal() as db:
            stmt = (
                select(CheckedIp)
                .order_by(CheckedIp.id.asc())
                .execution_options(stream_results=True, yield_per=EXPORT_STREAM_BATCH)
            )

            # Open the file after DB is ready; append mode
            with open(Path(EXPORT_FILE).expanduser(), "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                if file_needs_header(EXPORT_FILE):
                    writer.writeheader()

                for r in db.execute(stmt).scalars():
                    try:
                        writer.writerow(row_to_dict(r, export_ts))
                        wrote += 1
                    except Exception as row_err:
                        skipped += 1
                        print(f"[export_checked][ROW-ERROR] id={getattr(r,'id',None)} err={row_err}")
                        continue

        print(
            f"[export_checked] Appended {wrote} rows → {EXPORT_FILE} "
            f"(skipped={skipped}, export_ts={export_ts.isoformat()})"
        )
        return wrote

    except Exception as e:
        print(f"[export_checked][ERROR] export_once failed: {e}")
        traceback.print_exc()
        return 0


def main():
    interval = EXPORT_INTERVAL_SECONDS
    print(f"[export_checked] Starting append export every {interval}s → {EXPORT_FILE}")

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
                print(f"[export_checked][FATAL-LOOP-ERROR] {e}")
                traceback.print_exc()

                print(f"[export_checked] Retrying in {retry_sleep:.1f}s …")
                time.sleep(retry_sleep)
                retry_sleep = min(RETRY_MAX_SECONDS, retry_sleep * 2)

    except KeyboardInterrupt:
        print("\n[export_checked] Stopped by user.")


if __name__ == "__main__":
    main()