from datetime import datetime
from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from app.db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="User")  # "User" or "Admin"
    is_active = Column(Boolean, default=True)  # Allow admin to disable accounts
    date_joined = Column(DateTime, default=datetime.utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True, nullable=False)
    ip = Column(String, nullable=False)
    score = Column(Integer, nullable=False)
    status = Column(String, nullable=False)  # "Excellent", "Bon", "Moyen", "Critique"
    scan_type = Column(String, nullable=False)  # "excellent", "bon", "moyen", "critique"
    breakdown = Column(JSON, nullable=False)
    details = Column(JSON, nullable=True)
    date = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    type = Column(String, nullable=False)  # e.g. "directory_listing", "server_info", "insecure_form", "php_version", "apache_version"
    severity = Column(String, nullable=False)  # "high", "medium", "low"
    description = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    file_path = Column(String, nullable=False)  # Path to generated PDF
    generated_at = Column(DateTime, default=datetime.utcnow)
