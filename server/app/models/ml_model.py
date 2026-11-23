import uuid

from sqlalchemy import Boolean, Column, DateTime, Float, String, func
from sqlalchemy.dialects.postgresql import UUID

from app.models.user import Base


class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    version = Column(String(50), nullable=False)
    s3_key = Column(String(512), nullable=False)
    f1_score = Column(Float, nullable=True)
    is_active = Column(Boolean, default=False, nullable=False)
    trained_at = Column(DateTime(timezone=True), nullable=True)
    deployed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=True)
