"""
自定义检测模板数据库模型
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean
from app.database import Base


class CustomTemplate(Base):
    __tablename__ = "custom_templates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    template_id = Column(String(128), unique=True, index=True, nullable=False)
    name = Column(String(256), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(16), default="medium")
    tags = Column(JSON, default=list)
    content = Column(Text, nullable=False)
    format = Column(String(16), default="yaml")
    enabled = Column(Boolean, default=True)
    author = Column(String(128), default="")
    version = Column(String(32), default="1.0")
    match_count = Column(Integer, default=0)
    last_matched_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
