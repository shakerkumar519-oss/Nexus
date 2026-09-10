import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class DeviceCreate(BaseModel):
    name: str
    vendor: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unclassified"
    os_version: Optional[str] = ""
    criticality: Optional[str] = "Medium"
    ip_address: Optional[str] = ""


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    vendor: str
    device_type: str
    os_version: str
    criticality: str
    ip_address: str


class ConceptOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    concept: str
    raw_line: str
    verdict: str
    confidence: float


class ConfigurationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_id: int
    detected_vendor: str
    line_count: int
    uploaded_at: datetime.datetime
    is_baseline: bool


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_id: int
    finding_key: str
    title: str
    severity: str
    framework: str
    evidence: str
    why_it_matters: str
    recommendation: str
    asset: str
    attack_path_involved: bool
    risk_score: float
    estimated_impact: float
    status: str


class SimulationRequest(BaseModel):
    finding_ids: List[int]


class SimulationResult(BaseModel):
    baseline_risk: float
    simulated_risk: float
    risk_reduction_pct: float
    baseline_attack_paths: int
    simulated_attack_paths: int
    exposure_before: str
    exposure_after: str


class MappingDecision(BaseModel):
    status: str  # accepted | rejected | edited
    corrected_concept: Optional[str] = None
    corrected_label: Optional[str] = None


class UnknownMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    raw_command: str
    suggested_concept: str
    suggested_label: str
    confidence: float
    status: str


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
