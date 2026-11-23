import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.user import Base


class ReportedUrl(Base):
    __tablename__ = "reported_urls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    scan_log_id = Column(UUID(as_uuid=True), ForeignKey("scan_logs.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)
    reason = Column(String(1000), nullable=True)
    reported_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # relationships
    user = relationship("User", back_populates="reported_urls")
    scan_log = relationship("ScanLog", back_populates="reported_urls")
    feedback_queue = relationship(
        "FeedbackQueue", back_populates="reported_url", uselist=False, lazy="selectin"
    )


class FeedbackQueue(Base):
    __tablename__ = "feedback_queue"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    reported_url_id = Column(
        UUID(as_uuid=True), ForeignKey("reported_urls.id"), unique=True, nullable=False
    )
    url = Column(String(2048), nullable=False)
    vt_verdict = Column(String(50), nullable=True)
    is_approved = Column(Boolean, nullable=True)
    is_reported_to_kisa = Column(Boolean, default=False, nullable=False)
    queued_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)

    # relationships
    reported_url = relationship("ReportedUrl", back_populates="feedback_queue")
