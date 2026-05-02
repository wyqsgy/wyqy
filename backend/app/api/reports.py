from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.task import ScanTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.models.report import Report
from app.ai.report_generator import AIReportGenerator
from app.utils.helper import gen_report_id
from app.config import RISK_LEVELS

router = APIRouter(prefix="/api/reports", tags=["reports"])
report_gen = AIReportGenerator()


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
            "risk_level": v.risk_level,
            "target_url": v.target_url,
            "detail": v.detail,
            "ai_confidence": v.ai_confidence,
        })

    summary = report_gen.generate_summary(vuln_list)
    risk_distribution = {}
    for v in vulns:
        level = v.risk_level
        risk_distribution[level] = risk_distribution.get(level, 0) + 1

    task_info = {
        "target": task.target,
        "created_at": str(task.created_at),
        "finished_at": str(task.finished_at),
    }

    ai_analyses = []
    for v in vulns:
        analysis = report_gen.generate_analysis(
            vuln_name=v.name,
            vuln_detail=v.detail or v.description,
            evidence=v.evidence or "",
            risk_level=v.risk_level,
            payload=v.payload or "",
            category=v.category,
        )
        ai_analyses.append({"vuln_id": v.vuln_id, "analysis": analysis})

    html_content = report_gen.generate_html_report(task_info, vuln_list, summary)

    report_id = gen_report_id()
    report = Report(
        report_id=report_id,
        task_id=task_id,
        title=f"VulnArk安全扫描报告 - {task.target}",
        summary=summary,
        total_vulns=len(vulns),
        risk_distribution=risk_distribution,
        target_info=task_info,
        ai_summary=summary,
        content_html=html_content,
        content_json={
            "task_info": task_info,
            "vulnerabilities": vuln_list,
            "ai_analyses": ai_analyses,
            "summary": summary,
            "risk_distribution": risk_distribution,
        },
    )
    db.add(report)
    db.commit()

    return {
        "code": 200,
        "message": "Report generated",
        "data": {"report_id": report_id, "total_vulns": len(vulns)},
    }


@router.get("/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.report_id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

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
        raise HTTPException(status_code=404, detail="Report not found")

    return HTMLResponse(content=report.content_html)


@router.get("/list/{task_id}")
def list_reports(task_id: str, db: Session = Depends(get_db)):
    reports = db.query(Report).filter(Report.task_id == task_id).order_by(Report.created_at.desc()).all()
    items = [{
        "report_id": r.report_id,
        "title": r.title,
        "total_vulns": r.total_vulns,
        "created_at": str(r.created_at),
    } for r in reports]

    return {"code": 200, "data": {"total": len(items), "items": items}}
