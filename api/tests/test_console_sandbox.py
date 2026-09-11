"""Console sandbox config and WS URL helpers."""

from app.core.config import Settings
from app.services.console_proxy import sandbox_console_ws_url


def test_console_sandbox_disabled_without_url() -> None:
    settings = Settings(
        console_enabled=True,
        console_sandbox_enabled=True,
        console_sandbox_url=None,
        app_env="development",
    )
    assert settings.console_enabled_effective is True
    assert settings.console_sandbox_enabled_effective is False


def test_console_sandbox_enabled_with_url() -> None:
    settings = Settings(
        console_enabled=True,
        console_sandbox_enabled=True,
        console_sandbox_url="http://console:8001",
        app_env="development",
    )
    assert settings.console_sandbox_enabled_effective is True


def test_console_sandbox_off_in_production_without_allow() -> None:
    settings = Settings(
        console_enabled=True,
        console_allow_in_production=False,
        console_sandbox_enabled=True,
        console_sandbox_url="http://console:8001",
        app_env="production",
    )
    assert settings.console_enabled_effective is False
    assert settings.console_sandbox_enabled_effective is False


def test_sandbox_console_ws_url_maps_http_without_query_token() -> None:
    assert sandbox_console_ws_url("http://console:8001") == "ws://console:8001/api/v1/ws/console"
    assert sandbox_console_ws_url("https://console.example") == "wss://console.example/api/v1/ws/console"
    assert (
        sandbox_console_ws_url("http://console:8001", token="abc.def")
        == "ws://console:8001/api/v1/ws/console?token=abc.def"
    )
