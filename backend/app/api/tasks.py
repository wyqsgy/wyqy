from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import Base, async_session_maker


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    scan_type: Mapped[str] = mapped_column(String(50), default="quick")
    options: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    logs: Mapped[list["TaskLog"]] = relationship("TaskLog", back_populates="task", cascade="all, delete-orphan")


class TaskLog(Base):
    __tablename__ = "task_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("tasks.id", ondelete="CASCADE"))
    level: Mapped[str] = mapped_column(String(20), default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    task: Mapped["Task"] = relationship("Task", back_populates="logs")


async def create_task(db: AsyncSession, name: str, target: str, scan_type: str, **options) -> Task:
    import uuid
    task = Task(
        id=str(uuid.uuid4()),
        name=name,
        target=target,
        scan_type=scan_type,
        options=options,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return task


async def get_tasks(db: AsyncSession, skip: int = 0, limit: int = 50, status: Optional[str] = None) -> tuple[list[Task], int]:
    from sqlalchemy import select, func, desc

    query = select(Task).order_by(desc(Task.created_at))
    count_query = select(func.count(Task.id))

    if status:
        query = query.where(Task.status == status)
        count_query = count_query.where(Task.status == status)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    tasks = result.scalars().all()

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    return list(tasks), total


async def get_task(db: AsyncSession, task_id: str) -> Optional[Task]:
    from sqlalchemy import select
    result = await db.execute(select(Task).where(Task.id == task_id))
    return result.scalar_one_or_none()


async def update_task(db: AsyncSession, task_id: str, **kwargs) -> Optional[Task]:
    task = await get_task(db, task_id)
    if not task:
        return None

    for key, value in kwargs.items():
        if hasattr(task, key):
            setattr(task, key, value)

    task.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(task)
    return task


async def delete_task(db: AsyncSession, task_id: str) -> bool:
    task = await get_task(db, task_id)
    if not task:
        return False

    await db.delete(task)
    await db.commit()
    return True
