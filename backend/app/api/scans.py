from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("")
def list_vulnerabilities(task_id: str = None, category: str = None,
                         risk_level: str = None, skip: int = 0, limit: int = 50,
                         db: Session = Depends(get_db)):
    query = db.query(Vulnerability).order_by(Vulnerability.created_at.desc())
    if task_id:
        query = query.filter(Vulnerability.task_id == task_id)
    if category:
        query = query.filter(Vulnerability.category == category)
    if risk_level:
        query = query.filter(Vulnerability.risk_level == risk_level)

    total = query.count()
    vulns = query.offset(skip).limit(limit).all()

    items = []
    for v in vulns:
        items.append({
            "vuln_id": v.vuln_id,
            "task_id": v.task_id,
            "name": v.name,
            "category": v.category,
            "module": v.module,
            "risk_level": v.risk_level,
            "risk_score": v.risk_score,
            "target_url": v.target_url,
            "description": v.description,
            "detail": v.detail,
            "payload": v.payload,
            "evidence": v.evidence,
            "fix_suggestion": v.fix_suggestion,
            "cve_ids": v.cve_ids or [],
            "ai_analysis": v.ai_analysis,
            "ai_confidence": v.ai_confidence,
            "is_confirmed": v.is_confirmed,
            "created_at": str(v.created_at) if v.created_at else None,
        })

    return {"code": 200, "data": {"total": total, "items": items}}


@router.get("/{vuln_id}")
def get_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return {
        "code": 200,
        "data": {
            "vuln_id": vuln.vuln_id,
            "task_id": vuln.task_id,
            "name": vuln.name,
            "category": vuln.category,
            "module": vuln.module,
            "risk_level": vuln.risk_level,
            "risk_score": vuln.risk_score,
            "target_url": vuln.target_url,
            "description": vuln.description,
            "detail": vuln.detail,
            "payload": vuln.payload,
            "request_data": vuln.request_data,
            "response_snippet": vuln.response_snippet,
            "evidence": vuln.evidence,
            "fix_suggestion": vuln.fix_suggestion,
            "cve_ids": vuln.cve_ids or [],
            "references": vuln.references or [],
            "ai_analysis": vuln.ai_analysis,
            "ai_confidence": vuln.ai_confidence,
            "is_confirmed": vuln.is_confirmed,
            "raw_data": vuln.raw_data or {},
            "created_at": str(vuln.created_at) if vuln.created_at else None,
        },
    }
