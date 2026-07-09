from pydantic_settings import SettingsConfigDict, BaseSettings


class Settings(BaseSettings):
    nvd_api_key: str
    nvd_base_url: str
    database_url: str
    app_name: str = "datagile_practice"
    debug: bool = False
    nvd_timeout_seconds: int = 90
    nvd_max_retries: int = 2
    nvd_retry_sleep_seconds: int = 10
    nvd_results_per_page: int = 2000
    nvd_recent_sync_days: int = 1
    nvd_initial_load_months: int = 12
    nvd_chunk_days: int = 7
    nvd_scheduler_interval_hours: int = 24
    osv_base_url: str = "https://api.osv.dev"
    osv_timeout_seconds: int = 30
    async_database_url: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
