# app/db/session.py
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import time

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ipsuser:ipspass@db:5432/ips")

POOL_SIZE       = int(os.getenv("DB_POOL_SIZE", "10000"))        
MAX_OVERFLOW    = int(os.getenv("DB_MAX_OVERFLOW", "10000"))     
POOL_TIMEOUT    = int(os.getenv("DB_POOL_TIMEOUT", "30"))     
POOL_RECYCLE    = int(os.getenv("DB_POOL_RECYCLE", "1800"))
POOL_PRE_PING   = os.getenv("DB_POOL_PRE_PING", "true").lower() == "true"

engine = create_engine(
    DATABASE_URL,
    pool_size=POOL_SIZE,
    max_overflow=MAX_OVERFLOW,
    pool_timeout=POOL_TIMEOUT,
    pool_recycle=POOL_RECYCLE,
    pool_pre_ping=POOL_PRE_PING,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)

def wait_for_db(url: str, retries: int = 40, delay: float = 1.0):
    for i in range(1, retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as e:
            print(f"[{i}/{retries}] DB not ready: {e}")
            time.sleep(delay)
    raise RuntimeError("Database connection failed after retries.")