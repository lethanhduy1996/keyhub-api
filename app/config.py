from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    database_url: str = 'sqlite:///./local.db'
    jwt_secret: str = Field(min_length=32)
    key_pepper: str = Field(min_length=32)
    app_name: str = 'Independent Key Server'
    access_token_minutes: int = Field(default=20, ge=1, le=1440)
    refresh_token_days: int = Field(default=30, ge=1, le=90)
    allowed_origins: str = ''

    # Optional: Telegram BotFather bot, isolated to private admin chats.
    telegram_bot_token: str = ''
    telegram_webhook_secret: str = ''
    telegram_admin_ids: str = ''
    telegram_webhook_base_url: str = ''
    telegram_owner_email: str = ''


@lru_cache

def get_settings() -> Settings:
    return Settings()
