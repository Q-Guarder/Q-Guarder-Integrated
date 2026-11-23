import uuid

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship

from app.models.user import Base


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)
    risk_level = Column(String(20), nullable=False)  # SECURED, SUSPICIOUS, BLOCKED
    final_score = Column(Float, nullable=False)
    scan_source = Column(String(50), nullable=True)  # camera, clipboard, manual
    scanned_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # relationships
    user = relationship("User", back_populates="scan_logs")
    score_detail = relationship("ScoreDetail", back_populates="scan_log", uselist=False, lazy="selectin")
    reported_urls = relationship("ReportedUrl", back_populates="scan_log", lazy="selectin")


class ScoreDetail(Base):
    __tablename__ = "score_details"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_log_id = Column(
        UUID(as_uuid=True), ForeignKey("scan_logs.id"), unique=True, nullable=False
    )
    vt_detected_engines = Column(Integer, nullable=True)
    vt_total_engines = Column(Integer, nullable=True)
    vt_weighted_score = Column(Float, nullable=True)
    ml_probability = Column(Float, nullable=True)
    ml_weighted_score = Column(Float, nullable=True)
    weighting_case = Column(String(50), nullable=True)
    xai_features = Column(JSON, nullable=True)
    scored_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # relationships
    scan_log = relationship("ScanLog", back_populates="score_detail")
