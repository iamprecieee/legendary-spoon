import logging
import sys
from functools import lru_cache

from loguru import logger

from config.base import get_settings


class InterceptHandler(logging.Handler):
    """
    - Map standard logging level to Loguru level
    - Find the frame where the logging call was made
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

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
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

    for file in logging.root.manager.loggerDict.keys():
        logging.getLogger(file).handlers = []
        logging.getLogger(file).propagate = True

    logger.configure(
        handlers=[
            {
                "sink": sys.stdout,
                "format": "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <5}</level> | <cyan>{file}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
                "filter": lambda record: record["extra"].get("target") != "file",
            },
            {
                "sink": settings.log_file,
                "rotation": "10 MB",
                "retention": "10 days",
                "format": "{time:YYYY-MM-DD HH:mm:ss} | {level: <5} | {file}:{line} - {message}",
            },
        ]
    )
