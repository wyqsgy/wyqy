from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from app.knowledge.cve_db import cve_db

router = APIRouter(prefix="/api/cve", tags=["cve"])


@router.get("/search")
def search_cve(keyword: str = Query(..., min_length=1)):
    results = cve_db.search(keyword)
    return {
        "success": True,
        "total": len(results),
        "data": [
            {
                "cve_id": r.cve_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "cvss_score": r.cvss_score,
                "affected_component": r.affected_component,
                "affected_versions": r.affected_versions,
                "fixed_version": r.fixed_version,
                "poc_available": r.poc_available,
                "references": r.references,
                "tags": r.tags,
            }
            for r in results
        ],
    }


@router.get("/list")
def list_cves(
    severity: str = Query(None),
    component: str = Query(None),
    tag: str = Query(None),
):
    if severity:
        results = cve_db.get_by_severity(severity)
    elif component:
        results = cve_db.get_by_component(component)
    elif tag:
        results = cve_db.get_by_tag(tag)
    else:
        results = cve_db.list_all()

    return {
        "success": True,
        "total": len(results),
        "data": [
            {
                "cve_id": r.cve_id,
                "name": r.name,
                "severity": r.severity,
                "cvss_score": r.cvss_score,
                "affected_component": r.affected_component,
                "fixed_version": r.fixed_version,
                "poc_available": r.poc_available,
                "tags": r.tags,
            }
            for r in results
        ],
    }


@router.get("/{cve_id}")
def get_cve_detail(cve_id: str):
    record = cve_db.get_by_cve_id(cve_id)
    if not record:
        return JSONResponse(status_code=404, content={"success": False, "error": "CVE not found"})

    return {
        "success": True,
        "data": {
            "cve_id": record.cve_id,
            "name": record.name,
            "description": record.description,
            "severity": record.severity,
            "cvss_score": record.cvss_score,
            "affected_component": record.affected_component,
            "affected_versions": record.affected_versions,
            "fixed_version": record.fixed_version,
            "poc_available": record.poc_available,
            "references": record.references,
            "tags": record.tags,
        },
    }


@router.get("/stats/summary")
def cve_stats():
    all_cves = cve_db.list_all()
    severity_count = {}
    component_count = {}
    for r in all_cves:
        severity_count[r.severity] = severity_count.get(r.severity, 0) + 1
        component_count[r.affected_component] = component_count.get(r.affected_component, 0) + 1

    return {
        "success": True,
        "total": len(all_cves),
        "by_severity": severity_count,
        "by_component": component_count,
    }
