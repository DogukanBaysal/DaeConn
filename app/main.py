import os
from db.session import engine, wait_for_db
from db.models import Base

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ipsuser:ipspass@db:5432/ips")

if __name__ == "__main__":
    print("⏳ Waiting for database...")
    wait_for_db(DATABASE_URL)

    print("📦 Creating tables via SQLAlchemy ORM...")
    Base.metadata.create_all(bind=engine)

    print("🎉 Done. Tables & indexes ensured. (This container exits; Postgres stays up.)")