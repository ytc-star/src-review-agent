from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_secret: str = "dev-secret-change-me"
    admin_username: str = "admin"
    admin_password: str = "admin"
    database_url: str = "sqlite:///./data/reviews.db"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-5-mini"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

