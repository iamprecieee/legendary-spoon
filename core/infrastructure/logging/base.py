import logging
import sys
from functools import lru_cache

from loguru import logger

from config.base import get_settings

from .context import request_context
from .format import CustomLogFormat


class InterceptHandler(logging.Handler):
    """
    - Map standard logging level to Loguru level
    - Find the frame where the logging call was made
    - Auto-inject context data from contextvars
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        context_data = request_context.get({})

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage(), **context_data
        )


@lru_cache(maxsize=1)
def setup_logging() -> None:
    """
    Configures logging for the application:
    - Redirects standard logging to Loguru.
    - Sets up Loguru handlers for stdout and file logging.
    """

    settings = get_settings()

    logger.remove()  # Remove default Loguru handler

    logging.root.handlers = [InterceptHandler()]
    logging.root.setLevel(settings.logging_level)

    for name in logging.root.manager.loggerDict.keys():
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True

    def context_patcher(record):
        context_data = request_context.get({})
        record["extra"].update(context_data)

    handlers_config = []

    is_development_server = settings.environment.lower() in [
        "dev",
        "development",
        "local",
    ]
    handlers_config.append(
        {
            "backtrace": False,
            "colorize": True if is_development_server else False,
            "diagnose": True,
            "filter": lambda record: (
                record["extra"].get("target") != "file"
                and "changes detected" not in record["message"]
                and record["function"] != "callHandlers"
            ),
            "format": lambda record: CustomLogFormat(
                record=record
            ).log_console_format(),
            "serialize": False if is_development_server else True,
            "sink": sys.stdout,
        }
    )

    handlers_config.append(
        {
            "backtrace": True,
            "colorize": False,
            "compression": "zip",
            "diagnose": True,
            "enqueue": True,
            "filter": lambda record: (
                "changes detected" not in record["message"]
                and record["function"] != "callHandlers"
            ),
            "format": lambda record: CustomLogFormat(record=record).log_file_format(),
            "level": "INFO",
            "retention": "10 days",
            "rotation": "10 MB",
            "serialize": True,
            "sink": settings.log_file,
        }
    )

    error_log_file = str(settings.log_file).replace(".log", "_errors.log")
    handlers_config.append(
        {
            "backtrace": True,
            "colorize": False,
            "compression": "zip",
            "diagnose": True,
            "enqueue": True,
            "filter": lambda record: record["level"].no >= 40,
            "format": lambda record: CustomLogFormat(record=record).log_file_format(),
            "level": "ERROR",
            "retention": "60 days",
            "rotation": "10 MB",
            "serialize": True,
            "sink": error_log_file,
        }
    )

    logger.configure(handlers=handlers_config, patcher=context_patcher)
