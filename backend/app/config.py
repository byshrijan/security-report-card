from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Security Report Card API"


settings = Settings()
