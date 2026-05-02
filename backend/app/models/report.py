from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), unique=True, index=True)
    task_id = Column(String(64), index=True)
    title = Column(String(256), nullable=False)
    summary = Column(Text, default="")
    total_vulns = Column(Integer, default=0)
    risk_distribution = Column(JSON, default=dict)
    target_info = Column(JSON, default=dict)
    ai_summary = Column(Text, default="")
    content_html = Column(Text, default="")
    content_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
