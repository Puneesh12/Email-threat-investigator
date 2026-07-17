import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from app.db.session import Base

class Investigation(Base):
    """
    SQLAlchemy model representing email threat investigations.
    """
    __tablename__ = "investigations"

    # UUID primary key support (fallback to string UUID representation for SQLite)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(255), nullable=True)
    sender = Column(String(255), nullable=False, index=True)
    recipient = Column(String(255), nullable=False, index=True)
    subject = Column(String(500), nullable=True)
    date_sent = Column(String(100), nullable=True)
    
    risk_score = Column(Integer, default=0, index=True)
    risk_level = Column(String(50), default="Low", index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    raw_headers = Column(Text, nullable=True)
    analysis_summary = Column(Text, nullable=True)
    
    # Store complete structured analysis metrics (headers, hops, IOCs, threat intel results)
    full_report_json = Column(JSON, nullable=True)

    def to_dict(self):
        """Converts model to dictionary."""
        return {
            "id": self.id,
            "filename": self.filename,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "date_sent": self.date_sent,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "raw_headers": self.raw_headers,
            "analysis_summary": self.analysis_summary,
            "full_report_json": self.full_report_json
        }
