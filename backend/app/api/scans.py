import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.ai.packet_verifier import ai_verifier, PacketEvidence
from app.ai.engine import ai_engine
from app.utils.logger import get_logger

logger = get_logger("vuln_api")
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


@router.post("/{vuln_id}/ai-verify")
def ai_verify_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    evidence = _build_evidence_from_vuln(vuln)

    result = ai_verifier.verify_with_ai(evidence, ai_engine)

    vuln.ai_analysis = json.dumps({
        "vulnerability_type": result.vulnerability_type,
        "confidence": result.confidence,
        "risk_level": result.risk_level,
        "evidence_summary": result.evidence_summary,
        "matched_patterns": result.matched_patterns,
        "cve_ids": result.cve_ids,
        "cvss_score": result.cvss_score,
        "remediation": result.remediation,
    }, ensure_ascii=False)
    vuln.ai_confidence = int(result.confidence * 100)
    vuln.is_confirmed = 1 if result.is_vulnerable and result.confidence >= 0.7 else (0 if not result.is_vulnerable else vuln.is_confirmed)
    db.commit()

    logger.info(f"AI verification completed for {vuln_id}: type={result.vulnerability_type}, confidence={result.confidence}")

    return {
        "code": 200,
        "data": {
            "vuln_id": vuln_id,
            "is_vulnerable": result.is_vulnerable,
            "vulnerability_type": result.vulnerability_type,
            "confidence": round(result.confidence * 100, 1),
            "risk_level": result.risk_level,
            "evidence_summary": result.evidence_summary,
            "matched_patterns": result.matched_patterns,
            "cve_ids": result.cve_ids,
            "cvss_score": result.cvss_score,
            "remediation": result.remediation,
            "is_confirmed": vuln.is_confirmed,
        },
    }


def _build_evidence_from_vuln(vuln: Vulnerability) -> PacketEvidence:
    request_method = "GET"
    request_url = vuln.target_url or ""
    request_headers = {}
    request_body = None

    if vuln.request_data:
        try:
            req_data = json.loads(vuln.request_data)
            request_method = req_data.get("method", "GET")
            request_url = req_data.get("url", request_url)
            request_headers = req_data.get("headers", {})
            request_body = req_data.get("body")
        except (json.JSONDecodeError, TypeError):
            pass

    response_status = 0
    response_headers = {}
    response_body = vuln.response_snippet or ""

    if vuln.raw_data:
        try:
            raw = vuln.raw_data
            if isinstance(raw, dict):
                response_status = raw.get("status_code", 0)
                response_headers = raw.get("headers", {})
                if raw.get("body"):
                    response_body = raw.get("body")
        except Exception:
            pass

    return PacketEvidence(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_body=request_body,
        response_status=response_status,
        response_headers=response_headers,
        response_body=response_body,
    )
