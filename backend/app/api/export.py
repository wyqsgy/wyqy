import io
import csv
import json
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse, JSONResponse
from app.database import SessionLocal
from app.models.vulnerability import Vulnerability
from app.models.task import ScanTask

router = APIRouter(prefix="/api/export", tags=["export"])


@router.get("/vulnerabilities")
def export_vulnerabilities(
    task_id: str = Query(None),
    risk_level: str = Query(None),
    format: str = Query("json", regex="^(json|csv)$"),
):
    db = SessionLocal()
    try:
        query = db.query(Vulnerability)
        if task_id:
            query = query.filter(Vulnerability.task_id == task_id)
        if risk_level:
            query = query.filter(Vulnerability.risk_level == risk_level)

        vulns = query.all()

        rows = []
        for v in vulns:
            rows.append({
                "vuln_id": v.vuln_id,
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
                "cve_ids": v.cve_ids,
                "ai_analysis": v.ai_analysis,
                "ai_confidence": v.ai_confidence,
                "fix_suggestion": v.fix_suggestion,
            })

        if format == "csv":
            output = io.StringIO()
            if rows:
                writer = csv.DictWriter(output, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            else:
                output.write("No vulnerabilities found\n")
            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
            )

        return JSONResponse(content={"total": len(rows), "vulnerabilities": rows})
    finally:
        db.close()


@router.get("/report/{task_id}")
def export_task_report(task_id: str, format: str = Query("json", regex="^(json|csv)$")):
    db = SessionLocal()
    try:
        task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
        if not task:
            return JSONResponse(status_code=404, content={"error": "Task not found"})

        vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()

        report = {
            "task_id": task.task_id,
            "target": task.target,
            "status": task.status.value if hasattr(task.status, 'value') else task.status,
            "started_at": str(task.created_at) if task.created_at else None,
            "finished_at": str(task.finished_at) if task.finished_at else None,
            "summary": {
                "total": task.vuln_count,
                "critical": task.critical_count,
                "high": task.high_count,
                "medium": task.medium_count,
                "low": task.low_count,
            },
            "vulnerabilities": [
                {
                    "name": v.name,
                    "risk_level": v.risk_level,
                    "target_url": v.target_url,
                    "detail": v.detail,
                    "cve_ids": v.cve_ids,
                    "fix_suggestion": v.fix_suggestion,
                    "ai_analysis": v.ai_analysis,
                }
                for v in vulns
            ],
        }

        if format == "csv":
            output = io.StringIO()
            flat_rows = []
            for v in vulns:
                flat_rows.append({
                    "task_id": task_id,
                    "target": task.target,
                    "name": v.name,
                    "risk_level": v.risk_level,
                    "target_url": v.target_url,
                    "detail": v.detail,
                    "cve_ids": v.cve_ids or "",
                    "fix_suggestion": v.fix_suggestion or "",
                })
            if flat_rows:
                writer = csv.DictWriter(output, fieldnames=flat_rows[0].keys())
                writer.writeheader()
                writer.writerows(flat_rows)
            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=report_{task_id[:8]}.csv"},
            )

        return JSONResponse(content=report)
    finally:
        db.close()
