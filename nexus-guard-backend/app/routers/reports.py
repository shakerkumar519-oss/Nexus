from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from . import compliance as compliance_router
from . import remediation as remediation_router
from .dna import compute_dna

router = APIRouter(prefix="/reports", tags=["Reports"])

VALID_TYPES = ["executive", "technical", "compliance", "device", "remediation"]


@router.get("/generate")
def generate_report(report_type: str = "executive", db: Session = Depends(get_db)):
    report_type = report_type.lower()
    if report_type not in VALID_TYPES:
        report_type = "executive"

    devices = db.query(models.Device).all()
    findings = db.query(models.Finding).filter(models.Finding.status == "open").all()
    critical = [f for f in findings if f.severity == "Critical"]
    attack_paths = [f for f in findings if f.attack_path_involved]

    base = {
        "report_type": report_type,
        "device_count": len(devices),
        "open_findings": len(findings),
        "critical_findings": len(critical),
        "attack_paths": len(attack_paths),
    }

    if report_type == "executive":
        top_fix = max(findings, key=lambda f: f.estimated_impact, default=None)
        base["summary"] = {
            "top_recommendation": top_fix.title if top_fix else "No open findings",
            "top_recommendation_impact_pct": top_fix.estimated_impact if top_fix else 0,
            "overall_compliance": compliance_router.compliance_dashboard(db).get("overall"),
        }
    elif report_type == "technical":
        base["findings"] = [{
            "id": f.id, "title": f.title, "device_id": f.device_id, "severity": f.severity,
            "evidence": f.evidence, "risk_score": f.risk_score,
        } for f in findings]
    elif report_type == "compliance":
        base["frameworks"] = compliance_router.compliance_dashboard(db)
    elif report_type == "device":
        base["devices"] = [{
            "id": d.id, "name": d.name, "vendor": d.vendor,
            "dna": compute_dna([f for f in findings if f.device_id == d.id]),
        } for d in devices]
    elif report_type == "remediation":
        base["remediation_ranking"] = remediation_router.remediation_ranking(db)

    return base
