from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.ai.packet_verifier import ai_verifier, PacketEvidence
from app.ai.engine import ai_engine
from app.models.vulnerability import Vulnerability
from app.core.vuln_verifier import (
    verify_vulnerability, quick_verify, batch_verify,
    VerificationResult, VerificationReport, get_verification_stats,
)
from app.utils.logger import get_logger

logger = get_logger("verify_api")
router = APIRouter(prefix="/api/verify", tags=["verify"])


class PacketVerifyRequest(BaseModel):
    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict = {}
    request_body: str | None = None
    response_status: int = 0
    response_headers: dict = {}
    response_body: str | None = None
    response_time_ms: float = 0.0
    raw_request: str | None = None
    raw_response: str | None = None
    use_ai: bool = True


class BatchVerifyRequest(BaseModel):
    packets: list[PacketVerifyRequest]
    use_ai: bool = False


@router.post("/packet")
def verify_single_packet(req: PacketVerifyRequest):
    evidence = PacketEvidence(
        request_method=req.request_method,
        request_url=req.request_url,
        request_headers=req.request_headers,
        request_body=req.request_body,
        response_status=req.response_status,
        response_headers=req.response_headers,
        response_body=req.response_body,
        response_time_ms=req.response_time_ms,
        raw_request=req.raw_request,
        raw_response=req.raw_response,
    )

    if req.use_ai:
        result = ai_verifier.verify_with_ai(evidence, ai_engine)
    else:
        result = ai_verifier.verify_packet(evidence)

    return {
        "code": 200,
        "data": {
            "is_vulnerable": result.is_vulnerable,
            "vulnerability_type": result.vulnerability_type,
            "confidence": round(result.confidence * 100, 1),
            "risk_level": result.risk_level,
            "evidence_summary": result.evidence_summary,
            "matched_patterns": result.matched_patterns,
            "cve_ids": result.cve_ids,
            "cvss_score": result.cvss_score,
            "remediation": result.remediation,
            "ai_enhanced": req.use_ai,
        },
    }


@router.post("/batch")
def verify_batch_packets(req: BatchVerifyRequest):
    results = []
    for packet in req.packets:
        evidence = PacketEvidence(
            request_method=packet.request_method,
            request_url=packet.request_url,
            request_headers=packet.request_headers,
            request_body=packet.request_body,
            response_status=packet.response_status,
            response_headers=packet.response_headers,
            response_body=packet.response_body,
            response_time_ms=packet.response_time_ms,
            raw_request=packet.raw_request,
            raw_response=packet.raw_response,
        )

        if req.use_ai:
            result = ai_verifier.verify_with_ai(evidence, ai_engine)
        else:
            result = ai_verifier.verify_packet(evidence)

        results.append({
            "request_url": packet.request_url,
            "is_vulnerable": result.is_vulnerable,
            "vulnerability_type": result.vulnerability_type,
            "confidence": round(result.confidence * 100, 1),
            "risk_level": result.risk_level,
            "evidence_summary": result.evidence_summary,
            "matched_patterns": result.matched_patterns,
        })

    vuln_count = sum(1 for r in results if r["is_vulnerable"])
    return {
        "code": 200,
        "data": {
            "total": len(results),
            "vulnerable_count": vuln_count,
            "results": results,
        },
    }


@router.post("/raw")
def verify_raw_packet(req: PacketVerifyRequest):
    """
    Accept raw HTTP request/response text and parse automatically.
    """
    evidence = PacketEvidence(
        request_method=req.request_method,
        request_url=req.request_url,
        request_headers=req.request_headers,
        request_body=req.request_body,
        response_status=req.response_status,
        response_headers=req.response_headers,
        response_body=req.response_body,
        response_time_ms=req.response_time_ms,
        raw_request=req.raw_request,
        raw_response=req.raw_response,
    )

    if req.raw_request and not req.request_url:
        parsed = _parse_raw_http(req.raw_request)
        evidence.request_method = parsed.get("method", "GET")
        evidence.request_url = parsed.get("url", "")
        evidence.request_headers = parsed.get("headers", {})
        evidence.request_body = parsed.get("body")

    if req.raw_response and not req.response_status:
        parsed = _parse_raw_http(req.raw_response)
        evidence.response_status = parsed.get("status_code", 0)
        evidence.response_headers = parsed.get("headers", {})
        evidence.response_body = parsed.get("body")

    if req.use_ai:
        result = ai_verifier.verify_with_ai(evidence, ai_engine)
    else:
        result = ai_verifier.verify_packet(evidence)

    return {
        "code": 200,
        "data": {
            "is_vulnerable": result.is_vulnerable,
            "vulnerability_type": result.vulnerability_type,
            "confidence": round(result.confidence * 100, 1),
            "risk_level": result.risk_level,
            "evidence_summary": result.evidence_summary,
            "matched_patterns": result.matched_patterns,
            "cve_ids": result.cve_ids,
            "cvss_score": result.cvss_score,
            "remediation": result.remediation,
            "ai_enhanced": req.use_ai,
        },
    }


def _parse_raw_http(raw: str) -> dict:
    import re
    result = {"method": "GET", "url": "", "headers": {}, "body": "", "status_code": 0}

    try:
        parts = raw.split("\r\n\r\n", 1)
        header_section = parts[0]
        result["body"] = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\r\n")
        first_line = lines[0]

        status_match = re.match(r"HTTP/[\d.]+ (\d{3})", first_line)
        if status_match:
            result["status_code"] = int(status_match.group(1))
        else:
            method_match = re.match(r"(\w+) ([^\s]+)", first_line)
            if method_match:
                result["method"] = method_match.group(1)
                result["url"] = method_match.group(2)

        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                result["headers"][key.strip()] = value.strip()
    except Exception:
        pass

    return result


class VulnVerifyRequest(BaseModel):
    target_url: str
    method: str = "GET"
    category: str
    original_payload: str
    original_response: str
    headers: dict = {}
    risk_level: str = "medium"
    timeout: int = 15


class BatchVulnVerifyRequest(BaseModel):
    findings: list[VulnVerifyRequest]
    max_concurrent: int = 5


@router.post("/vulnerability")
def verify_single_vulnerability(req: VulnVerifyRequest):
    """Deep multi-stage verification of a single vulnerability finding."""
    report = verify_vulnerability(
        target_url=req.target_url,
        method=req.method,
        category=req.category,
        original_payload=req.original_payload,
        original_response=req.original_response,
        headers=req.headers or None,
        risk_level=req.risk_level,
        timeout=req.timeout,
    )

    return {
        "code": 200,
        "data": {
            "result": report.result.value,
            "confidence_score": report.confidence_score,
            "false_positive_reason": report.false_positive_reason,
            "recommendations": report.recommendations,
            "evidences": [
                {
                    "strategy": e.strategy.value,
                    "description": e.description,
                    "supports_finding": e.supports_finding,
                    "confidence_impact": e.confidence_impact,
                    "details": e.details,
                }
                for e in report.evidences
            ],
        },
    }


@router.post("/vulnerability/quick")
def quick_verify_vulnerability(req: VulnVerifyRequest):
    """Quick passive verification without sending additional requests."""
    report = quick_verify(
        target_url=req.target_url,
        category=req.category,
        original_payload=req.original_payload,
        original_response=req.original_response,
        risk_level=req.risk_level,
    )

    return {
        "code": 200,
        "data": {
            "result": report.result.value,
            "confidence_score": report.confidence_score,
            "false_positive_reason": report.false_positive_reason,
            "recommendations": report.recommendations,
            "evidences": [
                {
                    "strategy": e.strategy.value,
                    "description": e.description,
                    "supports_finding": e.supports_finding,
                    "confidence_impact": e.confidence_impact,
                }
                for e in report.evidences
            ],
        },
    }


@router.post("/vulnerability/batch")
def batch_verify_vulnerabilities(req: BatchVulnVerifyRequest):
    """Batch deep verification of multiple vulnerability findings."""
    findings = [
        {
            "target_url": f.target_url,
            "method": f.method,
            "category": f.category,
            "payload": f.original_payload,
            "response": f.original_response,
            "headers": f.headers or None,
            "risk_level": f.risk_level,
        }
        for f in req.findings
    ]

    reports = batch_verify(findings, max_concurrent=req.max_concurrent)
    stats = get_verification_stats(reports)

    return {
        "code": 200,
        "data": {
            "stats": stats,
            "results": [
                {
                    "target_url": r.original_finding.get("target_url", ""),
                    "category": r.original_finding.get("category", ""),
                    "result": r.result.value,
                    "confidence_score": r.confidence_score,
                    "false_positive_reason": r.false_positive_reason,
                    "recommendations": r.recommendations,
                }
                for r in reports
            ],
        },
    }


@router.post("/vulnerability/{vuln_id}")
def reverify_existing_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    """Re-verify an existing vulnerability from the database with deep verification."""
    vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞记录不存在")

    report = verify_vulnerability(
        target_url=vuln.target_url or "",
        method="GET",
        category=vuln.category,
        original_payload=vuln.payload or "",
        original_response=vuln.response_snippet or "",
        risk_level=vuln.risk_level,
    )

    vuln.verification_result = report.result.value
    vuln.confidence_score = report.confidence_score
    vuln.false_positive_reason = report.false_positive_reason
    vuln.verification_evidences = [
        {
            "strategy": e.strategy.value,
            "description": e.description,
            "supports_finding": e.supports_finding,
            "confidence_impact": e.confidence_impact,
        }
        for e in report.evidences
    ]
    db.commit()

    return {
        "code": 200,
        "data": {
            "vuln_id": vuln_id,
            "result": report.result.value,
            "confidence_score": report.confidence_score,
            "false_positive_reason": report.false_positive_reason,
            "recommendations": report.recommendations,
            "evidences": [
                {
                    "strategy": e.strategy.value,
                    "description": e.description,
                    "supports_finding": e.supports_finding,
                    "confidence_impact": e.confidence_impact,
                }
                for e in report.evidences
            ],
        },
    }


@router.get("/vulnerability/{vuln_id}/status")
def get_verification_status(vuln_id: str, db: Session = Depends(get_db)):
    """Get the verification status of an existing vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞记录不存在")

    return {
        "code": 200,
        "data": {
            "vuln_id": vuln_id,
            "name": vuln.name,
            "category": vuln.category,
            "risk_level": vuln.risk_level,
            "verification_result": vuln.verification_result,
            "confidence_score": vuln.confidence_score,
            "false_positive_reason": vuln.false_positive_reason,
            "verification_evidences": vuln.verification_evidences or [],
        },
    }
