# config.py — Environment-driven configuration for the XSW Honeypot.
# All values can be overridden via environment variables or a .env file.


from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "XSW Honeypot"
    app_version: str = "1.0.0"
    debug: bool = False

    # ── Honeypot Endpoint ─────────────────────────────────────────────────────
    # The fake ACS path advertised in your SP metadata to attract attackers
    honeypot_path: str = "/saml/acs"
    # Never validate signatures — the whole point is to capture everything
    validate_signatures: bool = False
    # Max payload size accepted (bytes) — prevents memory exhaustion attacks
    max_payload_bytes: int = 512_000  # 500 KB

    # ── Storage ───────────────────────────────────────────────────────────────
    # Redis for fast assertion ID dedup and capture storage
    redis_url: str = "redis://localhost:6379/0"
    # How long to keep raw captures in Redis (seconds). Default: 30 days
    capture_ttl_seconds: int = 60 * 60 * 24 * 30
    # Also persist captures to disk as JSON (useful without Redis)
    persist_to_disk: bool = True
    captures_dir: str = "captures"

    # ── Alerting ──────────────────────────────────────────────────────────────
    # Webhook URL (Slack, Discord, Teams, custom) for real-time alerts
    alert_webhook_url: Optional[str] = None
    # Only alert when XSW indicators are detected (False = alert on ALL hits)
    alert_on_xsw_only: bool = False
    # Minimum severity score (0–100) to trigger an alert
    alert_min_severity: int = 0

    # ── Dashboard ─────────────────────────────────────────────────────────────
    dashboard_enabled: bool = True
    dashboard_path: str = "/dashboard"
    # Basic auth for the dashboard (leave empty to disable auth)
    dashboard_username: str = ""
    dashboard_password: str = ""

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    # Max requests per IP per minute before returning 429
    rate_limit_per_minute: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
