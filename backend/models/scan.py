"""
Scan-related database models
"""

from enum import Enum
from typing import Optional

from sqlalchemy import Column, String, Text, JSON, Boolean, Integer, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship

from models.base import BaseModel, GUID


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"


class ScanType(str, Enum):
    """Professional Security Scan Types for Bug Bounty & Penetration Testing"""
    
    # Basic Scans
    RECONNAISSANCE = "reconnaissance"           # 5-10 min: Basic subdomain + port discovery
    VULNERABILITY = "vulnerability"            # 30-60 min: Comprehensive vulnerability assessment
    FULL = "full"                             # 1-2 hours: Complete security audit
    
    # Professional Bug Bounty Scans
    DEEP_RECON = "deep_recon"                 # 15-30 min: Advanced subdomain + infrastructure analysis
    SECRETS_SCAN = "secrets_scan"             # 20-45 min: Comprehensive secrets detection
    WEB_SECURITY = "web_security"             # 30-60 min: CORS, CSP, WAF analysis
    EXPLOITATION = "exploitation"             # 45-90 min: AI-guided vulnerability exploitation
    ZERO_DAY_HUNT = "zero_day_hunt"          # 2-4 hours: Advanced zero-day discovery


class Target(BaseModel):
    """Target model for scan targets"""
    
    __tablename__ = "targets"
    
    # Basic fields
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    scope = Column(JSON)  # List of in-scope domains/IPs
    out_of_scope = Column(JSON)  # List of out-of-scope items
    is_active = Column(Boolean, default=True)
    
    # Advanced fields - previously missing
    priority = Column(String(20), default="medium")  # low, medium, high, critical
    max_depth = Column(Integer, default=5)  # Maximum scan depth
    contact_email = Column(String(255))  # Security contact email
    rate_limit = Column(Integer, default=5)  # Requests per second limit
    authentication_required = Column(Boolean, default=False)  # Requires auth
    api_config = Column(JSON)  # API authentication configuration
    notes = Column(Text)  # Additional notes
    
    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(BaseModel):
    """Scan model for tracking scanning activities"""
    
    __tablename__ = "scans"
    
    name = Column(String(255), nullable=False)
    target_id = Column(GUID(), ForeignKey("targets.id"), nullable=False)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    
    # Configuration
    config = Column(JSON)  # Scan configuration parameters
    
    # Progress tracking
    total_steps = Column(Integer, default=0)
    completed_steps = Column(Integer, default=0)
    progress_percentage = Column(Integer, default=0)
    
    # Results
    results = Column(JSON)  # Scan results summary
    error_message = Column(Text)
    
    # Metadata
    started_at = Column(String)  # ISO timestamp when scan started
    completed_at = Column(String)  # ISO timestamp when scan completed
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Finding(BaseModel):
    """Finding model for reconnaissance results"""
    
    __tablename__ = "findings"
    
    scan_id = Column(GUID(), ForeignKey("scans.id"), nullable=False)
    finding_type = Column(String(100), nullable=False)  # subdomain, port, service, etc.
    value = Column(String(500), nullable=False)  # The actual finding
    source = Column(String(100))  # Tool/method that found it
    confidence = Column(Integer, default=100)  # Confidence level 0-100
    extra_data = Column(JSON)  # Additional data about the finding
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")


class Vulnerability(BaseModel):
    """Vulnerability model for security findings"""
    
    __tablename__ = "vulnerabilities"
    
    scan_id = Column(GUID(), ForeignKey("scans.id"), nullable=False)
    
    # Basic vulnerability info
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    cvss_score = Column(String(10))
    cve_id = Column(String(20))
    
    # Location
    url = Column(String(1000))
    parameter = Column(String(255))
    method = Column(String(10))  # GET, POST, etc.
    
    # Evidence
    poc = Column(Text)  # Proof of concept
    evidence = Column(JSON)  # Screenshots, responses, etc.
    
    # Classification
    category = Column(String(100))  # SQLi, XSS, SSRF, etc.
    confidence = Column(Integer, default=100)
    false_positive = Column(Boolean, default=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities") 