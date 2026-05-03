from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.task import ScanTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.models.report import Report
from app.ai.report_generator import generate_html_report, save_report, generate_report_id
from app.utils.helper import gen_report_id
from app.config import RISK_LEVELS

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/generate/{task_id}")
def generate_report(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()

    vuln_list = []
    for v in vulns:
        vuln_list.append({
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
            "fix_suggestion": v.fix_suggestion,
            "cve_ids": v.cve_ids or [],
            "references": v.references or [],
            "ai_confidence": v.ai_confidence,
            "evidence": v.evidence,
        })

    risk_distribution = {}
    for v in vulns:
        level = v.risk_level
        risk_distribution[level] = risk_distribution.get(level, 0) + 1

    task_info = {
        "target": task.target,
        "created_at": str(task.created_at),
        "finished_at": str(task.finished_at),
    }

    summary = f"本次安全评估针对 {task.target} 进行，共发现 {len(vulns)} 个安全漏洞。"
    if risk_distribution.get("critical"):
        summary += f" 其中严重漏洞 {risk_distribution['critical']} 个，需立即修复。"
    if risk_distribution.get("high"):
        summary += f" 高危漏洞 {risk_distribution['high']} 个，需紧急处理。"

    fingerprint = task.fingerprint or None

    result = save_report(
        task_id=task_id,
        task_info=task_info,
        vulnerabilities=vuln_list,
        fingerprint=fingerprint,
        summary=summary,
    )

    report = Report(
        report_id=result["report_id"],
        task_id=task_id,
        title=f"WyqYan安全扫描报告 - {task.target}",
        summary=summary,
        total_vulns=len(vulns),
        risk_distribution=risk_distribution,
        target_info=task_info,
        ai_summary=summary,
        content_html="",
        content_json={
            "task_info": task_info,
            "vulnerabilities": vuln_list,
            "summary": summary,
            "risk_distribution": risk_distribution,
        },
    )
    db.add(report)
    db.commit()

    return {
        "code": 200,
        "message": "报告生成成功",
        "data": {
            "report_id": result["report_id"],
            "total_vulns": len(vulns),
            "risk_distribution": risk_distribution,
        },
    }


@router.get("/list/{task_id}")
def list_reports(task_id: str, db: Session = Depends(get_db)):
    reports = db.query(Report).filter(Report.task_id == task_id).order_by(Report.created_at.desc()).all()
    items = [{
        "report_id": r.report_id,
        "title": r.title,
        "total_vulns": r.total_vulns,
        "risk_distribution": r.risk_distribution,
        "created_at": str(r.created_at),
    } for r in reports]

    return {"code": 200, "data": {"total": len(items), "items": items}}


@router.get("/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="报告未找到")

    return {
        "code": 200,
        "data": {
            "report_id": report.report_id,
            "task_id": report.task_id,
            "title": report.title,
            "summary": report.summary,
            "total_vulns": report.total_vulns,
            "risk_distribution": report.risk_distribution,
            "ai_summary": report.ai_summary,
            "created_at": str(report.created_at),
        },
    }


@router.get("/{report_id}/html")
def get_report_html(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="报告未找到")

    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == report.task_id).all()
    vuln_list = []
    for v in vulns:
        vuln_list.append({
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
            "fix_suggestion": v.fix_suggestion,
            "cve_ids": v.cve_ids or [],
            "references": v.references or [],
            "evidence": v.evidence,
        })

    task_info = {
        "target": report.target_info.get("target", "N/A") if report.target_info else "N/A",
        "created_at": report.target_info.get("created_at", "N/A") if report.target_info else "N/A",
        "finished_at": report.target_info.get("finished_at", "N/A") if report.target_info else "N/A",
    }

    html = generate_html_report(
        task_info=task_info,
        vulnerabilities=vuln_list,
        summary=report.summary or "",
        report_id=report.report_id,
    )

    return HTMLResponse(content=html)


@router.get("/{report_id}/json")
def get_report_json(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="报告未找到")

    return JSONResponse(content={
        "code": 200,
        "data": report.content_json or {},
    })


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="报告未找到")

    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == report.task_id).all()
    vuln_list = []
    for v in vulns:
        vuln_list.append({
            "vuln_id": v.vuln_id,
            "name": v.name,
            "risk_level": v.risk_level,
            "risk_score": v.risk_score,
            "target_url": v.target_url,
            "description": v.description,
            "detail": v.detail,
            "payload": v.payload,
            "fix_suggestion": v.fix_suggestion,
            "cve_ids": v.cve_ids or [],
            "references": v.references or [],
        })

    task_info = {
        "target": report.target_info.get("target", "N/A") if report.target_info else "N/A",
        "created_at": report.target_info.get("created_at", "N/A") if report.target_info else "N/A",
        "finished_at": report.target_info.get("finished_at", "N/A") if report.target_info else "N/A",
    }

    html = generate_html_report(
        task_info=task_info,
        vulnerabilities=vuln_list,
        summary=report.summary or "",
        report_id=report.report_id,
    )

    from fastapi.responses import Response
    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Disposition": f"attachment; filename=WyqYan_Report_{report.report_id}.html"
        },
    )
