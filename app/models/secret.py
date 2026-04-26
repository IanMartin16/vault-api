from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, JSON, Boolean, UniqueConstraint, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.db.session import Base

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    environment = Column(String(50), default="production")  # dev, staging, production
    
    # DEK salt for deriving project-specific encryption key
    dek_salt = Column(String(255), nullable=False)
    
    # Metadata
    color = Column(String(7), default="#3B82F6")  # Hex color for UI
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = relationship("User", back_populates="projects")
    secrets = relationship("Secret", back_populates="project", cascade="all, delete-orphan")

class Secret(Base):
    __tablename__ = "secrets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    key = Column(String(255), nullable=False, index=True)
    description = Column(String(500))
    
    # Encrypted data
    encrypted_value = Column(JSON, nullable=False)  # {ciphertext, nonce}
    
    # Versioning
    version = Column(Integer, default=1, nullable=False)
    
    # Metadata
    tags = Column(JSON, default=list)  # List of tags for organization
    is_deleted = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed_at = Column(DateTime)
    
    # Relationships
    project = relationship("Project", back_populates="secrets")
    versions = relationship("SecretVersion", back_populates="secret", cascade="all, delete-orphan")
    
    # Unique constraint: one key per project (excluding deleted)
    __table_args__ = (
        UniqueConstraint('project_id', 'key', name='uq_project_key'),
    )

class SecretVersion(Base):
    """Historical versions of secrets."""
    __tablename__ = "secret_versions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    secret_id = Column(UUID(as_uuid=True), ForeignKey("secrets.id"), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    version = Column(Integer, nullable=False)
    encrypted_value = Column(JSON, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    secret = relationship("Secret", back_populates="versions")

class AuditLog(Base):
    """Audit trail for all operations."""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True)
    secret_id = Column(UUID(as_uuid=True), ForeignKey("secrets.id"), nullable=True)
    
    # Request info
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100))
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    api_key_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Request/Response
    request_method = Column(String(10))
    request_path = Column(String(500))
    status_code = Column(Integer)
    
    # Additional metadata - RENOMBRADO
    event_metadata = Column("metadata", JSON, default=dict)  # ← CAMBIO AQUÍ
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
