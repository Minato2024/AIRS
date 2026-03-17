from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "AIRS - Adaptive Intrusion Response System"
    DEBUG: bool = False
    VERSION: str = "1.0.0"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./airs.db"
    # For PostgreSQL: "postgresql+asyncpg://user:pass@localhost/airs"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Honeypot Settings
    HONEYPOT_LOG_PATH: str = "./honeypot_logs"
    SUPPORTED_HONEYPOT_TYPES: List[str] = ["cowrie", "dionaea", "tpot", "custom"]
    
    # ML Model Paths
    MODEL_STORAGE_PATH: str = "./models"
    SIGNATURE_DB_PATH: str = "./signatures"
    
    # Detection Thresholds
    ANOMALY_THRESHOLD: float = 0.85
    CONFIDENCE_THRESHOLD: float = 0.90
    
    # Response Settings
    AUTO_RESPONSE_ENABLED: bool = True
    RESPONSE_COOLDOWN_SECONDS: int = 300  # Prevent response loops
    
    # Redis (for caching & task queue)
    REDIS_URL: str = "redis://localhost:6379/0"
    
    class Config:
        env_file = ".env"


settings = Settings()