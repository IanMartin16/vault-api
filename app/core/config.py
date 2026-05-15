from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from functools import lru_cache
from typing import Optional, Union

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )
    
    # ========================================
    # Application
    # ========================================
    PROJECT_NAME: str = "V-Secrets"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Production-ready secrets management API with encrypted storage, API key protection, audit logging, soft delete, and secret versioning."
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    
    # ========================================
    # Security
    # ========================================
    SECRET_KEY: str
    MASTER_ENCRYPTION_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    API_KEY_LENGTH: int = 32
    API_KEY_PEPPER: str
    
    # ========================================
    # Database
    # ========================================
    DATABASE_URL: str
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE: int = 3600
    DB_ECHO: bool = False
    
    # ========================================
    # Redis
    # ========================================
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL: int = 300
    
    # ========================================
    # Rate Limiting
    # ========================================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60
    
    RATE_LIMIT_FREE: int = 1000
    RATE_LIMIT_STARTER: int = 10000
    RATE_LIMIT_PRO: int = 100000
    RATE_LIMIT_ENTERPRISE: int = 1000000
    
    # ========================================
    # CORS - CORREGIDO
    # ========================================
    CORS_ORIGINS: Union[str, list[str]] = "http://localhost:3000,http://localhost:8000"
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]
    
    @field_validator('CORS_ORIGINS', mode='before')
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            # Si es string separado por comas
            if v.startswith('['):
                # Si parece JSON, parsearlo
                import json
                return json.loads(v)
            else:
                # Si es comma-separated
                return [origin.strip() for origin in v.split(',')]
        return v
    
    # ========================================
    # Monitoring & Logging
    # ========================================
    ENABLE_METRICS: bool = True
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    SENTRY_DSN: Optional[str] = None
    
    # ========================================
    # Audit Logging
    # ========================================
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_RETENTION_DAYS: int = 90
    AUDIT_LOG_SENSITIVE_FIELDS: list[str] = ["password", "secret", "token", "key"]
    
    # ========================================
    # Email
    # ========================================
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[str] = None
    EMAILS_FROM_NAME: Optional[str] = "Vault API"
    
    # ========================================
    # Feature Flags
    # ========================================
    ENABLE_REGISTRATION: bool = True
    ENABLE_SECRET_SHARING: bool = True
    ENABLE_WEBHOOKS: bool = False
    ENABLE_ROTATION: bool = False
    
    # ========================================
    # Plan Limits
    # ========================================
    MAX_PROJECTS_FREE: int = 2
    MAX_PROJECTS_STARTER: int = 10
    MAX_PROJECTS_PRO: int = 50

    MAX_SECRETS_FREE: int = 50
    MAX_SECRETS_STARTER: int = 200
    MAX_SECRETS_PRO: int = 1000

    MAX_API_KEYS_FREE: int = 3
    MAX_API_KEYS_STARTER: int = 10
    MAX_API_KEYS_PRO: int = 50

    MAX_SECRET_SIZE_BYTES: int = 65536
    MAX_SECRET_VERSIONS: int = 10

@lru_cache()
def get_settings() -> Settings:
    return Settings()