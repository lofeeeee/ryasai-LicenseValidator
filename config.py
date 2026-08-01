"""License Manager Configuration."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "License Manager"
    APP_VERSION: str = "2.0.0"
    SECRET_KEY: str = "change-me-in-production-super-secret"

    # Database (SQLite — lightweight, no external service needed)
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/license.db"

    # JWT
    JWT_SECRET: str = "jwt-secret-key-change-me"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # Admin (email only — password set via first-login setup)
    ADMIN_EMAIL: str = "admin@ryasai.com"

    # CORS
    CORS_ORIGINS: str = ""  # Comma-separated additional origins

    # Ed25519 signing key (DER-encoded, hex). Used to sign validation responses.
    # Generate: node -e "const c=require('crypto');const{k1,k2}=c.generateKeyPairSync('ed25519');console.log(k1.export({type:'spki',format:'der'}).toString('hex'));console.log(k2.export({type:'pkcs8',format:'der'}).toString('hex'))"
    LICENSE_SIGNING_PRIVATE_KEY: str = ""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 9000

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
