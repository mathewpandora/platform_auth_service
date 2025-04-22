from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from enum import Enum
from app.db.database import Base

class UserRole(str, Enum):
    CURATOR = "curator"
    CHAIRMAN_TEAM = "chairman_team"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)  # ✅
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    role = Column(String(50), default=UserRole.CURATOR.value)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    refresh_tokens = relationship("RefreshToken", back_populates="user")
