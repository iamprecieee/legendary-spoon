from typing import Any, Dict


class CustomLogFormat:
    """Manage custom log formatting for console and file outputs.

    Takes a Loguru record dictionary and formats it
    into human-readable strings for different logging sinks, including
    colorization for console output and contextual data for file output.
    """

    def __init__(self, record: Dict[str, Any]) -> None:
        """Initializes the CustomLogFormat with a Loguru record.

        Extracts and pre-processes various parts of the log record for formatting.

        Args:
            record: A dictionary representing the Loguru log record.
        """
        self.record = record
        self.time_str = self.record["time"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-4]
        self.level = self.record["level"].name
        level_colors = {
            "CRITICAL": "<red>",
            "DEBUG": "<white>",
            "ERROR": "<magenta>",
            "INFO": "<blue>",
            "SUCCESS": "<green>",
            "TRACE": "<dim>",
            "WARNING": "<yellow>",
        }
        self.level_color = level_colors.get(self.level, "<white>")
        self.function = self.record["function"]
        if self.function == "<module>":
            self.function = "\\<module\\>"

        self.location = f"{self.record['file']}:{self.function}:{self.record['line']}"

    def log_console_format(self) -> str:
        """Format the log record for console output.

        Includes timestamp, colored level, file location, and message.

        Returns
        -------
        str
            Formatted string suitable for console logging.
        """
        log_format = (
            f"<dim><bold>{self.time_str}</bold></dim> | "
            f"<level>{self.level_color}{self.level:8}</{self.level_color.strip('<>')}></level> | "
            f"<cyan>{self.location}</cyan> - "
            f"<level>{self.level_color}{self.record['message']}</{self.level_color.strip('<>')}></level>"
            "\n"
        )

        return log_format

    def log_file_format(self) -> str:
        """Format the log record for file output.

        Includes timestamp, level, file location, message, and extra context data (e.g., request ID).

        Returns
        -------
        str
            Formatted string suitable for file logging.
        """
        context_parts = []
        for key, value in self.record["extra"].items():
            if key not in ["request_id"]:
                context_parts.append(f"{key}={value}")

        context_string = f" | {', '.join(context_parts)}" if context_parts else ""

        log_format = (
            f"<dim><bold>{self.time_str}</bold></dim> | "
            f"<level>{self.level_color}{self.level:8}</{self.level_color.strip('<>')}></level> | "
            f"<cyan>{self.location}</cyan> - "
            f"<level>{self.level_color}{self.record['message']}</{self.level_color.strip('<>')}></level>"
            f"<bold><dim>{context_string}</dim></bold>"
            "\n"
        )

        return log_format
