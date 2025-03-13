from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "FastAPI Email Spam Filter"
    VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./test.db"  # Update this for your database
    DEBUG: bool = True

    class Config:
        env_file = ".env"  # Load environment variables from .env

# Create a global settings instance
settings = Settings()
