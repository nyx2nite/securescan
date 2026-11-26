import os
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models import User, Scan, Vulnerability, Report
from app.schemas import ScanRequest, ScanResponse, VulnerabilityResponse, ReportResponse
from app.scanner import run_scan
from app.reports import generate_pdf_report

router = APIRouter()

LOCAL_USERNAME = "local"


def get_local_user(db: Session = Depends(get_db)) -> User:
    """Single-user desktop app: every request runs as the local user (no login)."""
    user = db.query(User).filter(User.username == LOCAL_USERNAME).first()
    if not user:
        user = User(username=LOCAL_USERNAME, email="local@securescan.local", hashed_password="!", role="Admin")
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


def _get_scan(db: Session, scan_id: int) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _delete_scan_rows(db: Session, scan_id: int):
    for r in db.query(Report).filter(Report.scan_id == scan_id).all():
        try:
            os.remove(r.file_path)
        except OSError:
            pass
    db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
    db.query(Report).filter(Report.scan_id == scan_id).delete()


# ═══════════════════════════════ SCANS ═══════════════════════════════

@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(scan_req: ScanRequest, user: User = Depends(get_local_user), db: Session = Depends(get_db)):
    try:
        result = run_scan(scan_req.domain, scan_req.profile)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = Scan(
        domain=result["domain"],
        ip=result["ip"],
        score=result["score"],
        status=result["status"],
        scan_type=result["scan_type"],
        breakdown=result["breakdown"],
        details=result["details"],
        user_id=user.id,
    )
    db.add(scan)
    db.flush()
    db.add_all(
        Vulnerability(scan_id=scan.id, type=v["type"], severity=v["severity"],
                      description=v["description"], details=v.get("details"))
        for v in result["vulnerabilities"]
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.date.desc()).all()


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    return _get_scan(db, scan_id)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    _delete_scan_rows(db, scan_id)
    db.delete(scan)
    db.commit()


@router.delete("/scans", status_code=status.HTTP_204_NO_CONTENT)
def delete_all_scans(db: Session = Depends(get_db)):
    for scan in db.query(Scan).all():
        _delete_scan_rows(db, scan.id)
        db.delete(scan)
    db.commit()


@router.get("/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
def get_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    return db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()


# ═══════════════════════════════ REPORTS ═══════════════════════════════

@router.post("/reports", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def create_report(scan_id: int, user: User = Depends(get_local_user), db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    scan_data = {
        "domain": scan.domain,
        "ip": scan.ip,
        "score": scan.score,
        "status": scan.status,
        "breakdown": scan.breakdown,
        "details": scan.details,
        "date": scan.date,
        "vulnerabilities": [
            {"type": v.type, "severity": v.severity, "description": v.description, "details": v.details}
            for v in db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        ],
    }
    pdf_path = generate_pdf_report(scan_data)
    report = Report(scan_id=scan_id, user_id=user.id, file_path=pdf_path)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report.file_path, media_type="application/pdf", filename=os.path.basename(report.file_path))
