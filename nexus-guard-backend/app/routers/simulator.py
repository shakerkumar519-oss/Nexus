from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/simulator", tags=["What-if Simulator"])


def _org_risk_and_paths(findings):
    """Org-wide risk weights the single worst exposure more heavily than a
    flat average, since one unmitigated critical path typically dominates
    real-world exposure more than the mean of everything open."""
    if not findings:
        return 0.0, 0
    scores = [f.risk_score for f in findings]
    worst = max(scores)
    avg = sum(scores) / len(scores)
    org_risk = round(0.6 * worst + 0.4 * avg, 1)
    paths = len([f for f in findings if f.attack_path_involved])
    return org_risk, paths


def _exposure_label(risk: float) -> str:
    if risk >= 60:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    return "LOW"


@router.post("/run", response_model=schemas.SimulationResult)
def run_simulation(payload: schemas.SimulationRequest, db: Session = Depends(get_db)):
    """SIMULATED RESULT — NOT APPLIED TO PRODUCTION.
    Computes a hypothetical org risk state as if the selected findings were
    fixed, without writing anything to the database or any real device."""
    all_open = db.query(models.Finding).filter(models.Finding.status == "open").all()
    baseline_risk, baseline_paths = _org_risk_and_paths(all_open)

    remaining = [f for f in all_open if f.id not in set(payload.finding_ids)]
    simulated_risk, simulated_paths = _org_risk_and_paths(remaining)

    reduction_pct = 0.0
    if baseline_risk > 0:
        reduction_pct = round(max(0.0, (baseline_risk - simulated_risk) / baseline_risk * 100), 1)

    return schemas.SimulationResult(
        baseline_risk=baseline_risk,
        simulated_risk=simulated_risk,
        risk_reduction_pct=reduction_pct,
        baseline_attack_paths=baseline_paths,
        simulated_attack_paths=simulated_paths,
        exposure_before=_exposure_label(baseline_risk),
        exposure_after=_exposure_label(simulated_risk),
    )
