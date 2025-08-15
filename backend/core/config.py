"""
Configuration management for Nexus Hunter
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    app_name: str = "Nexus Hunter"
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=True, env="DEBUG")
    
    # Server
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"], 
        env="ALLOWED_ORIGINS"
    )
    
    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://nexus:nexus@localhost:5432/nexus_hunter",
        env="DATABASE_URL"
    )
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")
    
    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_password: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    
    # Celery
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1", env="CELERY_BROKER_URL"
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2", env="CELERY_RESULT_BACKEND"
    )
    
    # Security
    secret_key: str = Field(
        default="super-secret-key-change-in-production", env="SECRET_KEY"
    )
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE")
    
    # AI/ML
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    
    # External Tools
    nmap_path: str = Field(default="/usr/bin/nmap", env="NMAP_PATH")
    subfinder_path: str = Field(default="/usr/bin/subfinder", env="SUBFINDER_PATH")
    nuclei_path: str = Field(default="/usr/bin/nuclei", env="NUCLEI_PATH")
    
    # Rate Limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    
    # Scanning
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    scan_timeout: int = Field(default=3600, env="SCAN_TIMEOUT")  # 1 hour
    
    @validator("allowed_origins", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("environment")
    def validate_environment(cls, v):
        if v not in ["development", "staging", "production"]:
            raise ValueError("Environment must be development, staging, or production")
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings() 