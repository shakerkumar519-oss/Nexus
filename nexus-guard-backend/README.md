# NEXUS-GUARD X — Backend (SIH26155)

FastAPI + SQLAlchemy backend implementing the deterministic-rules-verify /
AI-assists architecture described in the product brief. Runs on SQLite with
zero setup for the demo; swap one env var to point it at PostgreSQL.

## Quick start (demo)

```bash
cd nexus-guard-backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # defaults to local SQLite, no edits needed

python seed.py                  # populates demo devices/findings/user
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/docs** for the interactive Swagger UI — every
endpoint below is callable directly from there.

Demo login: `admin` / `nexusguard123` (POST `/auth/login`).

## Switching to PostgreSQL

1. Create a database: `createdb nexusguard`
2. In `.env`, set:
   ```
   DATABASE_URL=postgresql://nexus_user:nexus_pass@localhost:5432/nexusguard
   ```
3. Re-run `python seed.py` — SQLAlchemy handles both engines identically, no
   code changes needed.

## What's implemented

| Area | Endpoint(s) | Notes |
|---|---|---|
| Auth | `POST /auth/login` | JWT bearer token |
| Devices | `GET/POST /devices`, `GET /devices/{id}/risk-summary` | |
| Config ingestion | `POST /configs/upload` | Multipart file upload → vendor detection → normalization → deterministic findings, all in one call |
| Normalization | `GET /configs/{id}/concepts` | Vendor-neutral security model for one config |
| Config diff | `GET /configs/diff?before_id=&after_id=` | Real `difflib` diff + before/after score + regression flag |
| Findings | `GET /findings`, `GET /findings/priority/ranked` | Filter by severity/framework/device/attack-path |
| Compliance | `GET /compliance/dashboard`, `GET /compliance/timeline` | Per-framework score + regression monitoring |
| Attack paths | `GET /attack-paths` | Built from findings flagged `attack_path_involved`, includes MITRE ATT&CK mapping |
| Security DNA | `GET /dna/device/{id}`, `GET /dna/organization` | 6-dimension score computed from open findings |
| Remediation | `GET /remediation/ranked`, `POST /remediation/{id}/mark-fixed` | Ranked by estimated risk-reduction impact |
| What-if simulator | `POST /simulator/run` | **Read-only** — computes a hypothetical org risk state, never writes to the DB or touches a device |
| AI Trainer | `POST /trainer/submit-unknown`, `GET /trainer/queue`, `POST /trainer/{id}/decision`, `GET /trainer/stats` | Heuristic keyword-based suggestion only; a human always Accepts/Edits/Rejects |
| Reports | `GET /reports/generate?report_type=executive\|technical\|compliance\|device\|remediation` | Aggregates live DB data into a report payload |

## Design principles carried over from the brief

- **AI assists, deterministic rules verify.** `app/security_rules.py` contains
  the rule engine — every finding shown to a user comes from a regex rule
  with an explicit severity/framework/evidence, not a model guess. The only
  place an AI-style heuristic proposes something is the Trainer queue for
  genuinely *unfamiliar* syntax, and it never auto-applies.
- **Simulations never touch production.** `/simulator/run` only reads open
  findings and returns a computed hypothetical — no device connection exists
  anywhere in this codebase.
- **Evidence-backed findings.** Every finding stores the matched config
  snippet, not just a verdict.
- **Framework mappings are demo data.** Control IDs like `CIS 9.2` in
  `security_rules.py` are illustrative for the prototype, not verified
  official control text — flag this to judges if asked.

## Wiring this to the frontend prototype

The frontend HTML currently uses in-memory demo data. To connect it:
replace the JS arrays (`DEVICES`, `FINDINGS`, etc.) with `fetch()` calls to
these endpoints, e.g.:

```js
fetch('http://127.0.0.1:8000/findings').then(r => r.json()).then(renderFindings);
```

Enable CORS is already open (`allow_origins=["*"]`) for local demo
convenience — tighten it before any real deployment.
