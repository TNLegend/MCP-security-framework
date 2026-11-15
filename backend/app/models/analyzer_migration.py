"""Prepared evidence and explicit decisions, never an active approval by themselves."""
from datetime import datetime
from uuid import uuid4
from sqlalchemy import String, Integer, JSON, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base


class AnalyzerMigration(Base):
    __tablename__ = 'analyzer_migrations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda:str(uuid4()))
    state: Mapped[str] = mapped_column(String(32), nullable=False, default='PREPARED')
    prepared_by: Mapped[str] = mapped_column(String(36), ForeignKey('control_plane_users.id'), nullable=False)
    prepared_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    packet_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    activated_revision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    activated_generation: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AnalyzerMigrationDecision(Base):
    __tablename__ = 'analyzer_migration_decisions'
    __table_args__ = (UniqueConstraint('migration_id','observation_id',name='uq_analyzer_migration_observation_decision'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda:str(uuid4()))
    migration_id: Mapped[str] = mapped_column(ForeignKey('analyzer_migrations.id'), nullable=False)
    observation_id: Mapped[int] = mapped_column(Integer, nullable=False)
    admin_id: Mapped[str] = mapped_column(ForeignKey('control_plane_users.id'), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    act: Mapped[dict] = mapped_column(JSON, nullable=False)
    signature: Mapped[str] = mapped_column(String, nullable=False)
    signature_key_id: Mapped[str] = mapped_column(String(128), nullable=False)


class AnalyzerMigrationActivation(Base):
    __tablename__ = 'analyzer_migration_activations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda:str(uuid4()))
    migration_id: Mapped[str] = mapped_column(ForeignKey('analyzer_migrations.id'), unique=True, nullable=False)
    admin_id: Mapped[str] = mapped_column(ForeignKey('control_plane_users.id'), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    revision_id: Mapped[str] = mapped_column(String(36), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
