from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, JSON
from app.database import Base


class CustomPOC(Base):
    __tablename__ = "custom_pocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    poc_id = Column(String(128), unique=True, index=True, nullable=False)
    name = Column(String(256), nullable=False)
    description = Column(Text, default="")
    risk_level = Column(String(32), default="medium")
    cve_ids = Column(JSON, default=list)
    cnvd_ids = Column(JSON, default=list)
    cvss_score = Column(String(16), default="0.0")
    tags = Column(JSON, default=list)
    affected_versions = Column(JSON, default=list)
    poc_type = Column(String(32), default="http")
    requests = Column(JSON, default=list)
    matchers = Column(JSON, default=list)
    references = Column(JSON, default=list)
    fix_suggestion = Column(Text, default="")
    disclosure_date = Column(String(32), default="")
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
