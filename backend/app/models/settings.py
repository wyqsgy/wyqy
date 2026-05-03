from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean
from app.database import Base


class AIModelConfig(Base):
    __tablename__ = "ai_model_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False)
    provider = Column(String(64), nullable=False)
    api_base = Column(String(512), nullable=False)
    api_key = Column(Text, default="")
    model_name = Column(String(128), nullable=False)
    temperature = Column(String(16), default="0.1")
    max_tokens = Column(String(16), default="4096")
    timeout = Column(String(16), default="60")
    is_enabled = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class InfoGatheringKey(Base):
    __tablename__ = "info_gathering_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform = Column(String(64), nullable=False)
    api_key = Column(Text, default="")
    email = Column(String(256), default="")
    is_enabled = Column(Boolean, default=True)
    extra_config = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SystemSettings(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(128), unique=True, nullable=False, index=True)
    value = Column(Text, default="")
    description = Column(String(512), default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
