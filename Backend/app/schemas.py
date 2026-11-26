from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict


class ScanRequest(BaseModel):
    domain: str
    profile: Literal["quick", "full"] = "full"


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    ip: str
    score: int
    status: str
    scan_type: str
    breakdown: dict
    details: Optional[dict] = None
    date: Optional[datetime] = None


class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    type: str
    severity: str
    description: str
    details: Optional[dict] = None


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    file_path: str
    generated_at: Optional[datetime] = None
