import json
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.custom_poc import CustomPOC
from app.core.poc_db import (
    POC, POCRequest, Matcher, MatcherType, POCType, RiskLevel,
    register_poc, get_poc, get_all_pocs, POC_DATABASE,
)
from app.utils.logger import get_logger

logger = get_logger("custom_poc_api")
router = APIRouter(prefix="/api/pocs", tags=["pocs"])


class POCRequestItem(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: dict = {}
    body: str | None = None


class MatcherItem(BaseModel):
    type: str = "word"
    value: str = ""
    part: str = "body"
    negative: bool = False


class CustomPOCRequest(BaseModel):
    name: str
    description: str = ""
    risk_level: str = "medium"
    cve_ids: list[str] = []
    cnvd_ids: list[str] = []
    cvss_score: str = "0.0"
    tags: list[str] = []
    affected_versions: list[str] = []
    poc_type: str = "http"
    requests: list[POCRequestItem] = []
    matchers: list[MatcherItem] = []
    references: list[str] = []
    fix_suggestion: str = ""
    disclosure_date: str = ""
    is_enabled: bool = True


def _custom_poc_to_internal(poc: CustomPOC) -> POC:
    risk_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "info": RiskLevel.INFO,
    }
    poc_type_map = {
        "http": POCType.HTTP,
        "dns": POCType.DNS,
        "tcp": POCType.TCP,
        "websocket": POCType.WEBSOCKET,
    }
    matcher_type_map = {
        "word": MatcherType.WORD,
        "regex": MatcherType.REGEX,
        "status": MatcherType.STATUS,
        "size": MatcherType.SIZE,
        "binary": MatcherType.BINARY,
        "dsl": MatcherType.DSL,
    }

    requests = []
    for r in (poc.requests or []):
        requests.append(POCRequest(
            method=r.get("method", "GET"),
            path=r.get("path", "/"),
            headers=r.get("headers", {}),
            body=r.get("body"),
        ))

    matchers = []
    for m in (poc.matchers or []):
        matchers.append(Matcher(
            type=matcher_type_map.get(m.get("type", "word"), MatcherType.WORD),
            value=m.get("value", ""),
            part=m.get("part", "body"),
            negative=m.get("negative", False),
        ))

    return POC(
        id=f"custom-{poc.poc_id}",
        name=poc.name,
        description=poc.description or "",
        risk_level=risk_map.get(poc.risk_level, RiskLevel.MEDIUM),
        cve_ids=poc.cve_ids or [],
        cnvd_ids=poc.cnvd_ids or [],
        cvss_score=float(poc.cvss_score or 0),
        tags=poc.tags or [],
        affected_versions=poc.affected_versions or [],
        poc_type=poc_type_map.get(poc.poc_type, POCType.HTTP),
        requests=requests,
        matchers=matchers,
        references=poc.references or [],
        fix_suggestion=poc.fix_suggestion or "",
        disclosure_date=poc.disclosure_date or "",
    )


def sync_custom_pocs_to_memory(db: Session):
    custom_pocs = db.query(CustomPOC).filter(CustomPOC.is_enabled == True).all()
    for cp in custom_pocs:
        internal_poc = _custom_poc_to_internal(cp)
        register_poc(internal_poc)
    logger.info(f"Synced {len(custom_pocs)} custom POCs to memory")


@router.get("")
def list_pocs(
    skip: int = 0,
    limit: int = 50,
    risk_level: str = None,
    tag: str = None,
    keyword: str = None,
    source: str = "all",
    db: Session = Depends(get_db),
):
    builtin_pocs = get_all_pocs()
    custom_pocs_db = db.query(CustomPOC).order_by(CustomPOC.created_at.desc()).all()

    result = []

    if source in ("all", "builtin"):
        for p in builtin_pocs:
            if p.id.startswith("custom-"):
                continue
            if risk_level and p.risk_level.value != risk_level:
                continue
            if tag and tag not in p.tags:
                continue
            if keyword and keyword.lower() not in p.name.lower() and keyword.lower() not in p.description.lower():
                continue
            result.append({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "risk_level": p.risk_level.value,
                "cve_ids": p.cve_ids,
                "cnvd_ids": p.cnvd_ids,
                "cvss_score": p.cvss_score,
                "tags": p.tags,
                "affected_versions": p.affected_versions,
                "poc_type": p.poc_type.value,
                "requests": [r.to_dict() for r in p.requests],
                "matchers": [
                    {"type": m.type.value, "value": m.value, "part": m.part, "negative": m.negative}
                    for m in p.matchers
                ],
                "references": p.references,
                "fix_suggestion": p.fix_suggestion,
                "disclosure_date": p.disclosure_date,
                "source": "builtin",
                "is_enabled": True,
            })

    if source in ("all", "custom"):
        for cp in custom_pocs_db:
            if risk_level and cp.risk_level != risk_level:
                continue
            if tag and tag not in (cp.tags or []):
                continue
            if keyword and keyword.lower() not in cp.name.lower() and keyword.lower() not in (cp.description or "").lower():
                continue
            result.append({
                "id": f"custom-{cp.poc_id}",
                "name": cp.name,
                "description": cp.description,
                "risk_level": cp.risk_level,
                "cve_ids": cp.cve_ids or [],
                "cnvd_ids": cp.cnvd_ids or [],
                "cvss_score": float(cp.cvss_score or 0),
                "tags": cp.tags or [],
                "affected_versions": cp.affected_versions or [],
                "poc_type": cp.poc_type,
                "requests": cp.requests or [],
                "matchers": cp.matchers or [],
                "references": cp.references or [],
                "fix_suggestion": cp.fix_suggestion,
                "disclosure_date": cp.disclosure_date,
                "source": "custom",
                "is_enabled": cp.is_enabled,
                "db_id": cp.id,
                "created_at": str(cp.created_at) if cp.created_at else None,
                "updated_at": str(cp.updated_at) if cp.updated_at else None,
            })

    total = len(result)
    result = result[skip:skip + limit]

    return {"code": 200, "data": {"total": total, "items": result}}


@router.get("/stats")
def get_poc_stats(db: Session = Depends(get_db)):
    builtin = [p for p in get_all_pocs() if not p.id.startswith("custom-")]
    custom_count = db.query(CustomPOC).count()

    risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for p in builtin:
        risk_dist[p.risk_level.value] = risk_dist.get(p.risk_level.value, 0) + 1

    custom_pocs = db.query(CustomPOC).all()
    for cp in custom_pocs:
        risk_dist[cp.risk_level] = risk_dist.get(cp.risk_level, 0) + 1

    return {
        "code": 200,
        "data": {
            "total": len(builtin) + custom_count,
            "builtin": len(builtin),
            "custom": custom_count,
            "risk_distribution": risk_dist,
        },
    }


@router.post("/custom")
def create_custom_poc(req: CustomPOCRequest, db: Session = Depends(get_db)):
    poc_id = str(uuid.uuid4())[:12]

    existing = db.query(CustomPOC).filter(CustomPOC.name == req.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="同名POC已存在")

    poc = CustomPOC(
        poc_id=poc_id,
        name=req.name,
        description=req.description,
        risk_level=req.risk_level,
        cve_ids=req.cve_ids,
        cnvd_ids=req.cnvd_ids,
        cvss_score=req.cvss_score,
        tags=req.tags,
        affected_versions=req.affected_versions,
        poc_type=req.poc_type,
        requests=[r.model_dump() for r in req.requests],
        matchers=[m.model_dump() for m in req.matchers],
        references=req.references,
        fix_suggestion=req.fix_suggestion,
        disclosure_date=req.disclosure_date,
        is_enabled=req.is_enabled,
    )
    db.add(poc)
    db.commit()
    db.refresh(poc)

    if req.is_enabled:
        internal_poc = _custom_poc_to_internal(poc)
        register_poc(internal_poc)

    logger.info(f"Custom POC created: {req.name} (id={poc_id})")
    return {"code": 200, "message": "自定义POC已创建", "data": {"id": f"custom-{poc_id}"}}


@router.put("/custom/{poc_db_id}")
def update_custom_poc(poc_db_id: int, req: CustomPOCRequest, db: Session = Depends(get_db)):
    poc = db.query(CustomPOC).filter(CustomPOC.id == poc_db_id).first()
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")

    poc.name = req.name
    poc.description = req.description
    poc.risk_level = req.risk_level
    poc.cve_ids = req.cve_ids
    poc.cnvd_ids = req.cnvd_ids
    poc.cvss_score = req.cvss_score
    poc.tags = req.tags
    poc.affected_versions = req.affected_versions
    poc.poc_type = req.poc_type
    poc.requests = [r.model_dump() for r in req.requests]
    poc.matchers = [m.model_dump() for m in req.matchers]
    poc.references = req.references
    poc.fix_suggestion = req.fix_suggestion
    poc.disclosure_date = req.disclosure_date
    poc.is_enabled = req.is_enabled
    poc.updated_at = datetime.utcnow()
    db.commit()

    POC_DATABASE.pop(f"custom-{poc.poc_id}", None)
    if req.is_enabled:
        internal_poc = _custom_poc_to_internal(poc)
        register_poc(internal_poc)

    logger.info(f"Custom POC updated: {req.name}")
    return {"code": 200, "message": "自定义POC已更新"}


@router.delete("/custom/{poc_db_id}")
def delete_custom_poc(poc_db_id: int, db: Session = Depends(get_db)):
    poc = db.query(CustomPOC).filter(CustomPOC.id == poc_db_id).first()
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")

    POC_DATABASE.pop(f"custom-{poc.poc_id}", None)
    db.delete(poc)
    db.commit()
    logger.info(f"Custom POC deleted: id={poc_db_id}")
    return {"code": 200, "message": "自定义POC已删除"}


@router.post("/custom/{poc_db_id}/toggle")
def toggle_custom_poc(poc_db_id: int, db: Session = Depends(get_db)):
    poc = db.query(CustomPOC).filter(CustomPOC.id == poc_db_id).first()
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")

    poc.is_enabled = not poc.is_enabled
    poc.updated_at = datetime.utcnow()
    db.commit()

    POC_DATABASE.pop(f"custom-{poc.poc_id}", None)
    if poc.is_enabled:
        internal_poc = _custom_poc_to_internal(poc)
        register_poc(internal_poc)

    return {"code": 200, "message": "POC状态已切换", "data": {"is_enabled": poc.is_enabled}}


@router.get("/custom/{poc_db_id}")
def get_custom_poc_detail(poc_db_id: int, db: Session = Depends(get_db)):
    poc = db.query(CustomPOC).filter(CustomPOC.id == poc_db_id).first()
    if not poc:
        raise HTTPException(status_code=404, detail="POC不存在")

    return {
        "code": 200,
        "data": {
            "id": f"custom-{poc.poc_id}",
            "db_id": poc.id,
            "name": poc.name,
            "description": poc.description,
            "risk_level": poc.risk_level,
            "cve_ids": poc.cve_ids or [],
            "cnvd_ids": poc.cnvd_ids or [],
            "cvss_score": poc.cvss_score,
            "tags": poc.tags or [],
            "affected_versions": poc.affected_versions or [],
            "poc_type": poc.poc_type,
            "requests": poc.requests or [],
            "matchers": poc.matchers or [],
            "references": poc.references or [],
            "fix_suggestion": poc.fix_suggestion,
            "disclosure_date": poc.disclosure_date,
            "is_enabled": poc.is_enabled,
            "created_at": str(poc.created_at) if poc.created_at else None,
            "updated_at": str(poc.updated_at) if poc.updated_at else None,
        },
    }
