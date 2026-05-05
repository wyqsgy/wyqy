"""
攻击链关联分析 API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.task import ScanTask
from app.models.vulnerability import Vulnerability
from app.core.correlation_engine import (
    analyze_correlations,
    export_chains_to_dict,
    get_chain_by_id,
)

router = APIRouter(prefix="/correlation", tags=["correlation"])


@router.get("/task/{task_id}")
def get_task_correlations(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    if task.correlation_data and task.correlation_data.get("chains_found", 0) > 0:
        return {"code": 200, "data": task.correlation_data}

    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()
    if not vulns:
        return {"code": 200, "data": {"chains_found": 0, "attack_chains": [], "message": "无漏洞数据"}}

    vuln_dicts = [
        {
            "vuln_id": v.vuln_id,
            "name": v.name,
            "category": v.category,
            "risk_level": v.risk_level,
            "target_url": v.target_url or "",
        }
        for v in vulns
    ]

    report = analyze_correlations(task_id, vuln_dicts)
    data = export_chains_to_dict(report)

    task.correlation_data = data
    db.commit()

    return {"code": 200, "data": data}


@router.get("/chain/{task_id}/{chain_id}")
def get_chain_detail(task_id: str, chain_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    if not task.correlation_data:
        raise HTTPException(status_code=404, detail="该任务暂无关联分析数据")

    chains = task.correlation_data.get("attack_chains", [])
    for chain in chains:
        if chain.get("chain_id") == chain_id:
            return {"code": 200, "data": chain}

    raise HTTPException(status_code=404, detail="攻击链不存在")


@router.post("/analyze/{task_id}")
def reanalyze_correlations(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")

    vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()
    if not vulns:
        return {"code": 200, "data": {"chains_found": 0, "message": "无漏洞数据"}}

    vuln_dicts = [
        {
            "vuln_id": v.vuln_id,
            "name": v.name,
            "category": v.category,
            "risk_level": v.risk_level,
            "target_url": v.target_url or "",
        }
        for v in vulns
    ]

    report = analyze_correlations(task_id, vuln_dicts)
    data = export_chains_to_dict(report)

    task.correlation_data = data
    db.commit()

    return {"code": 200, "data": data, "message": "关联分析完成"}
