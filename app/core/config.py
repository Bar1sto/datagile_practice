from pydantic_settings import SettingsConfigDict, BaseSettings


class Settings(BaseSettings):
    nvd_api_key: str
    database_url: str
    app_name: str = "datagile_practice"
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
