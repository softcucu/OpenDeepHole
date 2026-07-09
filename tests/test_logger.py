import logging
from types import SimpleNamespace

from backend import logger as logger_module


def test_setup_logging_suppresses_third_party_http_loggers(tmp_path, monkeypatch) -> None:
    app_logger = logging.getLogger("opendeephole")
    old_initialized = logger_module._initialized
    old_handlers = list(app_logger.handlers)
    old_levels = {
        name: logging.getLogger(name).level
        for name in logger_module._NOISY_HTTP_LOGGERS
    }

    def fake_config():
        return SimpleNamespace(
            logging=SimpleNamespace(
                level="DEBUG",
                file=str(tmp_path / "opendeephole.log"),
                max_size_mb=1,
                backup_count=1,
            )
        )

    for handler in old_handlers:
        app_logger.removeHandler(handler)
    logger_module._initialized = False
    monkeypatch.setattr(logger_module, "get_config", fake_config)
    for logger_name in logger_module._NOISY_HTTP_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.INFO)

    try:
        logger_module.setup_logging()

        for logger_name in logger_module._NOISY_HTTP_LOGGERS:
            assert logging.getLogger(logger_name).level == logging.WARNING
    finally:
        for handler in list(app_logger.handlers):
            app_logger.removeHandler(handler)
            handler.close()
        for handler in old_handlers:
            app_logger.addHandler(handler)
        for logger_name, level in old_levels.items():
            logging.getLogger(logger_name).setLevel(level)
        logger_module._initialized = old_initialized
