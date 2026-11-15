"""Database provenance links; never a replacement for an approval signature."""
from datetime import datetime
from sqlalchemy import ForeignKey,String,DateTime
from sqlalchemy.orm import Mapped,mapped_column
from app.db.database import Base

class ToolApprovalLineage(Base):
    __tablename__='tool_approval_lineage'
    approval_id: Mapped[int]=mapped_column(ForeignKey('tool_observation_review_approvals.id'),primary_key=True)
    source_approval_id: Mapped[int | None]=mapped_column(ForeignKey('tool_observation_review_approvals.id'),nullable=True)
    root_approval_id: Mapped[int]=mapped_column(ForeignKey('tool_observation_review_approvals.id'),nullable=False)
    original_admin_id: Mapped[str]=mapped_column(String(255),nullable=False)
    original_approved_at: Mapped[datetime]=mapped_column(DateTime,nullable=False)
    original_revision_id: Mapped[str]=mapped_column(String(64),nullable=False)
    recorded_by: Mapped[str]=mapped_column(String(255),nullable=False)
