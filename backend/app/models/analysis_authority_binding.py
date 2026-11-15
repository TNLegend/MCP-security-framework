"""Execution provenance kept separate from the immutable legacy evidence."""
from sqlalchemy import ForeignKey,BigInteger,String
from sqlalchemy.orm import Mapped,mapped_column
from app.db.database import Base

class AnalysisAuthorityBinding(Base):
    __tablename__='analysis_authority_bindings'
    analysis_id: Mapped[int]=mapped_column(ForeignKey('tool_analyses.id'),primary_key=True)
    generation: Mapped[int]=mapped_column(BigInteger,nullable=False)
    pipeline_identity: Mapped[str]=mapped_column(String(64),nullable=False)
