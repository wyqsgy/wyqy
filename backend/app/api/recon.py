from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter(prefix="/api/recon", tags=["recon"])


class PortScanRequest(BaseModel):
    host: str
    ports: Optional[List[int]] = None
    timeout: float = 1.5
    max_workers: int = 200


class FingerprintRequest(BaseModel):
    target_url: str
    timeout: int = 10


class SubdomainRequest(BaseModel):
    domain: str
    timeout: float = 2.0
    max_workers: int = 50


@router.post("/ports/scan")
def port_scan(req: PortScanRequest):
    from app.recon.port_scanner import scan_ports
    results = scan_ports(req.host, req.ports, req.timeout, req.max_workers)
    return {
        "code": 200,
        "data": {
            "host": req.host,
            "open_ports": len(results),
            "ports": results,
        },
    }


@router.post("/ports/quick")
def port_quick_scan(host: str = Query(...)):
    from app.recon.port_scanner import quick_scan
    results = quick_scan(host)
    return {
        "code": 200,
        "data": {
            "host": host,
            "open_ports": len(results),
            "ports": results,
        },
    }


@router.post("/fingerprint")
def fingerprint(req: FingerprintRequest):
    from app.recon.fingerprint import fingerprint_target
    result = fingerprint_target(req.target_url, req.timeout)
    return {"code": 200, "data": result}


@router.post("/subdomain")
def subdomain_enum(req: SubdomainRequest):
    from app.recon.subdomain import enumerate_subdomains
    result = enumerate_subdomains(req.domain, req.timeout, req.max_workers)
    return {"code": 200, "data": result}


@router.get("/subdomain/quick")
def subdomain_quick(domain: str = Query(...)):
    from app.recon.subdomain import quick_enum_subdomains
    result = quick_enum_subdomains(domain)
    return {"code": 200, "data": result}
