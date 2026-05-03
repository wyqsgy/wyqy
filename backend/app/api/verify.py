from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.ai.packet_verifier import ai_verifier, PacketEvidence
from app.ai.engine import ai_engine
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
