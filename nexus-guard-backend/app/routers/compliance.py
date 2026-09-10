from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db

router = APIRouter(prefix="/compliance", tags=["Compliance"])

FRAMEWORKS = ["CIS", "NIST", "STIG", "ISO"]


@router.get("/dashboard")
def compliance_dashboard(db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.status == "open").all()
    result = {}
    for fw in FRAMEWORKS:
        fw_findings = [f for f in findings if fw.lower() in f.framework.lower()]
        if not fw_findings:
            result[fw] = {"score": 100.0, "open_findings": 0}
            continue
        avg_risk = sum(f.risk_score for f in fw_findings) / len(fw_findings)
        result[fw] = {"score": round(max(0.0, 100 - avg_risk), 1), "open_findings": len(fw_findings)}

    if findings:
        overall = round(sum(v["score"] for v in result.values()) / len(result), 1)
    else:
        overall = 100.0
    result["overall"] = overall
    return result


@router.get("/timeline")
def compliance_timeline(db: Session = Depends(get_db)):
    """Regression monitoring: returns recorded org-wide compliance snapshots
    in order, flagging any drop greater than the configured threshold."""
    snapshots = db.query(models.ComplianceSnapshot).order_by(models.ComplianceSnapshot.taken_at).all()
    timeline = [{"taken_at": s.taken_at.isoformat(), "score": s.score} for s in snapshots]
    regressions = []
    threshold = 5.0
    for i in range(1, len(timeline)):
        drop = timeline[i - 1]["score"] - timeline[i]["score"]
        if drop >= threshold:
            regressions.append({
                "from": timeline[i - 1]["taken_at"], "to": timeline[i]["taken_at"],
                "drop": round(drop, 1),
            })
    return {"timeline": timeline, "regressions_detected": regressions}
