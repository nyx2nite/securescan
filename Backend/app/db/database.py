import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# The desktop app sets SECURESCAN_DATA_DIR to a writable per-user folder (%APPDATA%\SecureScan).
_DATA_DIR = os.getenv("SECURESCAN_DATA_DIR")
if _DATA_DIR:
    os.makedirs(_DATA_DIR, exist_ok=True)
    SQLALCHEMY_DATABASE_URL = "sqlite:///" + os.path.join(_DATA_DIR, "securescan.db").replace("\\", "/")
else:
    SQLALCHEMY_DATABASE_URL = "sqlite:///./securescan.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
