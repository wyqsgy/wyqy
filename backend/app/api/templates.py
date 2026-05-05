"""
自定义检测模板 API
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.models.custom_template import CustomTemplate
from app.core.template_engine import (
    TemplateParser,
    TemplateValidator,
    build_template_example,
)

router = APIRouter(prefix="/templates", tags=["templates"])


@router.get("/")
def list_templates(
    enabled: Optional[bool] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(CustomTemplate)

    if enabled is not None:
        query = query.filter(CustomTemplate.enabled == enabled)
    if severity:
        query = query.filter(CustomTemplate.severity == severity)
    if search:
        query = query.filter(
            (CustomTemplate.name.contains(search)) |
            (CustomTemplate.description.contains(search)) |
            (CustomTemplate.template_id.contains(search))
        )

    total = query.count()
    items = query.order_by(CustomTemplate.updated_at.desc()).offset(offset).limit(limit).all()

    return {
        "code": 200,
        "data": {
            "items": [
                {
                    "id": t.id,
                    "template_id": t.template_id,
                    "name": t.name,
                    "description": t.description,
                    "severity": t.severity,
                    "tags": t.tags or [],
                    "format": t.format,
                    "enabled": t.enabled,
                    "author": t.author,
                    "version": t.version,
                    "match_count": t.match_count,
                    "last_matched_at": str(t.last_matched_at) if t.last_matched_at else None,
                    "created_at": str(t.created_at),
                    "updated_at": str(t.updated_at),
                }
                for t in items
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    }


@router.get("/example")
def get_template_example():
    return {"code": 200, "data": {"example": build_template_example()}}


@router.get("/{template_id}")
def get_template(template_id: str, db: Session = Depends(get_db)):
    template = db.query(CustomTemplate).filter(
        CustomTemplate.template_id == template_id
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="模板不存在")

    return {
        "code": 200,
        "data": {
            "id": template.id,
            "template_id": template.template_id,
            "name": template.name,
            "description": template.description,
            "severity": template.severity,
            "tags": template.tags or [],
            "content": template.content,
            "format": template.format,
            "enabled": template.enabled,
            "author": template.author,
            "version": template.version,
            "match_count": template.match_count,
            "last_matched_at": str(template.last_matched_at) if template.last_matched_at else None,
            "created_at": str(template.created_at),
            "updated_at": str(template.updated_at),
        },
    }


@router.post("/")
def create_template(data: dict, db: Session = Depends(get_db)):
    template_id = data.get("template_id", "").strip()
    name = data.get("name", "").strip()
    content = data.get("content", "").strip()
    fmt = data.get("format", "yaml")

    if not template_id:
        raise HTTPException(status_code=400, detail="模板ID不能为空")
    if not name:
        raise HTTPException(status_code=400, detail="模板名称不能为空")
    if not content:
        raise HTTPException(status_code=400, detail="模板内容不能为空")

    existing = db.query(CustomTemplate).filter(
        CustomTemplate.template_id == template_id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="模板ID已存在")

    try:
        if fmt == "yaml":
            parsed = TemplateParser.parse_yaml(content)
        else:
            parsed = TemplateParser.parse_json(content)

        errors = TemplateValidator.validate(parsed)
        if errors:
            raise HTTPException(
                status_code=400,
                detail=f"模板验证失败: {'; '.join(errors)}",
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    template = CustomTemplate(
        template_id=template_id,
        name=name,
        description=data.get("description", parsed.description),
        severity=data.get("severity", parsed.severity.value),
        tags=data.get("tags", parsed.tags),
        content=content,
        format=fmt,
        enabled=data.get("enabled", True),
        author=data.get("author", ""),
        version=data.get("version", "1.0"),
    )

    db.add(template)
    db.commit()
    db.refresh(template)

    return {
        "code": 201,
        "data": {"template_id": template.template_id, "name": template.name},
        "message": "模板创建成功",
    }


@router.put("/{template_id}")
def update_template(template_id: str, data: dict, db: Session = Depends(get_db)):
    template = db.query(CustomTemplate).filter(
        CustomTemplate.template_id == template_id
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="模板不存在")

    if "content" in data:
        content = data["content"].strip()
        if not content:
            raise HTTPException(status_code=400, detail="模板内容不能为空")
        fmt = data.get("format", template.format)
        try:
            if fmt == "yaml":
                parsed = TemplateParser.parse_yaml(content)
            else:
                parsed = TemplateParser.parse_json(content)
            errors = TemplateValidator.validate(parsed)
            if errors:
                raise HTTPException(
                    status_code=400,
                    detail=f"模板验证失败: {'; '.join(errors)}",
                )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        template.content = content
        template.format = fmt

    for field in ["name", "description", "severity", "tags", "enabled", "author", "version"]:
        if field in data:
            setattr(template, field, data[field])

    db.commit()

    return {"code": 200, "data": {"template_id": template.template_id}, "message": "模板更新成功"}


@router.delete("/{template_id}")
def delete_template(template_id: str, db: Session = Depends(get_db)):
    template = db.query(CustomTemplate).filter(
        CustomTemplate.template_id == template_id
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="模板不存在")

    db.delete(template)
    db.commit()

    return {"code": 200, "message": "模板已删除"}


@router.post("/{template_id}/toggle")
def toggle_template(template_id: str, db: Session = Depends(get_db)):
    template = db.query(CustomTemplate).filter(
        CustomTemplate.template_id == template_id
    ).first()
    if not template:
        raise HTTPException(status_code=404, detail="模板不存在")

    template.enabled = not template.enabled
    db.commit()

    return {
        "code": 200,
        "data": {"template_id": template_id, "enabled": template.enabled},
        "message": f"模板已{'启用' if template.enabled else '禁用'}",
    }


@router.post("/validate")
def validate_template(data: dict):
    content = data.get("content", "").strip()
    fmt = data.get("format", "yaml")

    if not content:
        return {"code": 400, "data": {"valid": False, "errors": ["内容不能为空"]}}

    try:
        if fmt == "yaml":
            parsed = TemplateParser.parse_yaml(content)
        else:
            parsed = TemplateParser.parse_json(content)

        errors = TemplateValidator.validate(parsed)
        return {
            "code": 200,
            "data": {
                "valid": len(errors) == 0,
                "errors": errors,
                "parsed": {
                    "id": parsed.id,
                    "name": parsed.name,
                    "severity": parsed.severity.value,
                    "requests_count": len(parsed.requests),
                },
            },
        }
    except Exception as e:
        return {"code": 200, "data": {"valid": False, "errors": [str(e)]}}
