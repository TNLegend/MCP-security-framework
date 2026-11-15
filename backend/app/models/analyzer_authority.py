from datetime import datetime
from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base

class AnalyzerAuthority(Base):
    __tablename__='analyzer_authority'
    id: Mapped[int]=mapped_column(primary_key=True)
    generation: Mapped[int]=mapped_column(BigInteger,nullable=False)
    pipeline_identity: Mapped[str]=mapped_column(String(64),nullable=False)
    closure_digest: Mapped[str]=mapped_column(String(64),nullable=False)
    execution_digest: Mapped[str | None]=mapped_column(String(64),nullable=True)
    analyzer_revision: Mapped[str]=mapped_column(String(100),nullable=False)
    manifest_approval_ref: Mapped[str]=mapped_column(String(255),nullable=False)
    activated_by: Mapped[str]=mapped_column(String(36),nullable=False)
    activated_at: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow,nullable=False)
