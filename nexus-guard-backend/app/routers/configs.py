import difflib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from .. import models, schemas, security_rules
from ..database import get_db

router = APIRouter(prefix="/configs", tags=["Configurations"])


@router.post("/upload", response_model=schemas.ConfigurationOut)
async def upload_configuration(
    device_name: str = Form(...),
    vendor_hint: Optional[str] = Form(None),
    device_type: Optional[str] = Form("Unclassified"),
    criticality: Optional[str] = Form("Medium"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Ingest one raw configuration file, detect its vendor, normalize it
    into vendor-neutral concepts, and run the deterministic rule engine to
    produce Findings. This is the core 'Configuration -> Universal Security
    Model -> Compliance Evidence' pipeline described in the product brief."""
    raw_bytes = await file.read()
    try:
        raw_text = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(400, "Could not read file as text")

    device = db.query(models.Device).filter(models.Device.name == device_name).first()
    if not device:
        device = models.Device(
            name=device_name,
            vendor=vendor_hint or "Unknown",
            device_type=device_type or "Unclassified",
            criticality=criticality or "Medium",
        )
        db.add(device)
        db.commit()
        db.refresh(device)

    detected_vendor = security_rules.detect_vendor(raw_text)
    is_first = len(device.configurations) == 0

    config = models.Configuration(
        device_id=device.id,
        raw_text=raw_text,
        detected_vendor=vendor_hint or detected_vendor,
        line_count=len([l for l in raw_text.splitlines() if l.strip()]),
        is_baseline=is_first,
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    # Normalize -> universal security model
    for concept in security_rules.normalize_configuration(raw_text):
        db.add(models.NormalizedConcept(configuration_id=config.id, **concept))

    # Deterministic compliance verdicts -> findings
    for f in security_rules.run_compliance_rules(raw_text, device.criticality):
        db.add(models.Finding(
            device_id=device.id,
            configuration_id=config.id,
            **f,
        ))
    db.commit()

    # Record an org-wide compliance snapshot for regression monitoring
    _record_snapshot(db)

    db.refresh(config)
    return config


@router.get("/{config_id}/concepts", response_model=List[schemas.ConceptOut])
def get_concepts(config_id: int, db: Session = Depends(get_db)):
    concepts = db.query(models.NormalizedConcept).filter(
        models.NormalizedConcept.configuration_id == config_id
    ).all()
    return concepts


@router.get("/device/{device_id}", response_model=List[schemas.ConfigurationOut])
def list_configs_for_device(device_id: int, db: Session = Depends(get_db)):
    return db.query(models.Configuration).filter(
        models.Configuration.device_id == device_id
    ).order_by(models.Configuration.uploaded_at).all()


@router.get("/diff")
def diff_configurations(before_id: int, after_id: int, db: Session = Depends(get_db)):
    before = db.query(models.Configuration).get(before_id)
    after = db.query(models.Configuration).get(after_id)
    if not before or not after:
        raise HTTPException(404, "One or both configurations not found")

    diff_lines = list(difflib.unified_diff(
        before.raw_text.splitlines(), after.raw_text.splitlines(),
        lineterm="", n=1,
    ))

    before_findings = db.query(models.Finding).filter(models.Finding.configuration_id == before_id).all()
    after_findings = db.query(models.Finding).filter(models.Finding.configuration_id == after_id).all()

    def score(findings):
        if not findings:
            return 100.0
        penalty = sum(f.risk_score for f in findings) / max(len(findings), 1)
        return round(max(0.0, 100 - penalty), 1)

    before_score, after_score = score(before_findings), score(after_findings)

    return {
        "diff": diff_lines,
        "security_score_before": before_score,
        "security_score_after": after_score,
        "regression": round(after_score - before_score, 1),
        "regression_detected": after_score < before_score,
        "new_findings": [f.title for f in after_findings if f.finding_key not in {b.finding_key for b in before_findings}],
        "resolved_findings": [f.title for f in before_findings if f.finding_key not in {a.finding_key for a in after_findings}],
    }


def _record_snapshot(db: Session):
    findings = db.query(models.Finding).filter(models.Finding.status == "open").all()
    if not findings:
        org_score = 100.0
    else:
        avg_risk = sum(f.risk_score for f in findings) / len(findings)
        org_score = round(max(0.0, 100 - avg_risk), 1)
    db.add(models.ComplianceSnapshot(score=org_score))
    db.commit()
