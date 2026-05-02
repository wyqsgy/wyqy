from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/attack", tags=["attack"])


class WAFScanRequest(BaseModel):
    target_url: str
    timeout: int = 10


class WAFBypassRequest(BaseModel):
    target_url: str
    payload: str
    timeout: int = 10


class SSRFScanRequest(BaseModel):
    target_url: str
    timeout: int = 10


class JWTAnalyzeRequest(BaseModel):
    token: str


class HoneypotRequest(BaseModel):
    target_url: str
    timeout: int = 10


class FuzzRequest(BaseModel):
    target_url: str
    timeout: int = 10


class DeserialRequest(BaseModel):
    target_url: str
    timeout: int = 10


@router.post("/waf/detect")
def waf_detect(req: WAFScanRequest):
    from app.attack.waf_engine import detect_waf
    result = detect_waf(req.target_url, req.timeout)
    return {"code": 200, "data": result}


@router.post("/waf/bypass")
def waf_bypass(req: WAFBypassRequest):
    from app.attack.waf_engine import bypass_waf
    result = bypass_waf(req.target_url, req.payload, req.timeout)
    return {"code": 200, "data": result}


@router.post("/ssrf/scan")
def ssrf_scan(req: SSRFScanRequest):
    from app.attack.ssrf_chain import scan_ssrf
    results = scan_ssrf(req.target_url, req.timeout)
    return {"code": 200, "data": {"total": len(results), "findings": results}}


@router.post("/jwt/analyze")
def jwt_analyze(req: JWTAnalyzeRequest):
    from app.attack.jwt_engine import analyze_jwt
    result = analyze_jwt(req.token)
    return {"code": 200, "data": result}


@router.get("/jwt/endpoints")
def jwt_endpoints(target_url: str = Query(...)):
    from app.attack.jwt_engine import scan_jwt_endpoints
    results = scan_jwt_endpoints(target_url)
    return {"code": 200, "data": {"total": len(results), "endpoints": results}}


@router.post("/honeypot/detect")
def honeypot_detect(req: HoneypotRequest):
    from app.attack.honeypot_engine import detect_honeypot
    result = detect_honeypot(req.target_url, req.timeout)
    return {"code": 200, "data": result}


@router.post("/fuzz")
def smart_fuzz(req: FuzzRequest):
    from app.attack.fuzzer import smart_fuzz as do_fuzz
    result = do_fuzz(req.target_url, req.timeout)
    return {"code": 200, "data": result}


@router.post("/deserialization/scan")
def deserialization_scan(req: DeserialRequest):
    from app.attack.deserial_engine import scan_deserialization
    results = scan_deserialization(req.target_url, req.timeout)
    return {"code": 200, "data": {"total": len(results), "findings": results}}


@router.get("/privesc/scan")
def privesc_scan():
    from app.attack.linux_privesc import scan_linux_privesc
    result = scan_linux_privesc()
    return {"code": 200, "data": result}
