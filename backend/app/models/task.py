import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Enum, Text, JSON
from app.database import Base


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(64), unique=True, index=True, nullable=False)
    target = Column(String(512), nullable=False)
    categories = Column(JSON, default=list)
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    progress = Column(Integer, default=0)
    total_checks = Column(Integer, default=0)
    vuln_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    fingerprint = Column(JSON, default=dict)
    waf_info = Column(JSON, default=dict)
    correlation_data = Column(JSON, default=dict)
    priority_data = Column(JSON, default=dict)
    error_msg = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
