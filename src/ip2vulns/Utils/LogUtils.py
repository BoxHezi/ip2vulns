import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional


class SingletonMeta(type):
    """
    Thread-safe singleton metaclass.
    """
    _instances = {}
    _lock: threading.Lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]


class Ip2VulnsLogger(metaclass=SingletonMeta):
    """
    Thread-safe singleton logger for ip2vulns package.

    Usage:
        logger = Ip2VulnsLogger()
        logger.info("Message")

    Or:
        from .Utils.LogUtils import get_logger
        logger = get_logger()
        logger.info("Message")
    """

    def __init__(self, level: int = logging.INFO, log_file: Optional[str] = None):
        self._logger = logging.getLogger("ip2vulns")

        # Avoid duplicate handlers
        if not self._logger.handlers:
            self._setup_logger(level, log_file)

        self._logger.setLevel(level)

    def _setup_logger(self, level: int, log_file: Optional[str]) -> None:
        """Configure logger handlers and formatters."""
        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(message)s",
            "%Y-%m-%d %H:%M:%S"
        )

        # File handler
        if log_file is None:
            # Create logs directory if it doesn't exist
            logs_dir = Path("logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = f"{logs_dir}/ip2vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)

        # Add handlers
        self._logger.addHandler(file_handler)
        self._logger.addHandler(console_handler)

    def set_level(self, level: int) -> None:
        """Set logging level for all handlers."""
        self._logger.setLevel(level)
        for handler in self._logger.handlers:
            handler.setLevel(level)

    def debug(self, msg: str) -> None:
        """Log debug message."""
        msg = "[DEBUG] " + msg
        self._logger.debug(msg)

    def info(self, msg: str) -> None:
        """Log info message."""
        msg = "[INFO] " + msg
        self._logger.info(msg)

    def warning(self, msg: str) -> None:
        """Log warning message."""
        msg = "[WARN] " + msg
        self._logger.warning(msg)

    def error(self, msg: str) -> None:
        """Log error message."""
        msg = "[ERROR] " + msg
        self._logger.error(msg)

    def critical(self, msg: str) -> None:
        """Log critical message."""
        msg = "[CRITICAL] " + msg
        self._logger.critical(msg)

    def exception(self, msg: str) -> None:
        """Log exception with stack trace."""
        msg = "[EXCEPTION] " + msg
        self._logger.exception(msg)


# Global singleton instance
_logger_instance: Optional[Ip2VulnsLogger] = None


def init_logger(level: int = logging.INFO, log_file: Optional[str] = None) -> Ip2VulnsLogger:
    """
    Initialize the singleton logger.

    Args:
        level: Logging level (default: logging.INFO)
        log_file: Custom log file path (default: auto-generated)

    Returns:
        Ip2VulnsLogger: Singleton logger instance
    """
    global _logger_instance
    return Ip2VulnsLogger(level, log_file) if _logger_instance is None else _logger_instance


def get_logger() -> Ip2VulnsLogger:
    """
    Get the singleton logger instance.

    Returns:
        Ip2VulnsLogger: Singleton logger instance
    """
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = init_logger()

    return _logger_instance


# # Convenience functions
# def log_debug(msg: str) -> None:
#     """Log debug message using singleton logger."""
#     msg = "[DEBUG] " + msg
#     get_logger().debug(msg)


# def log_info(msg: str) -> None:
#     """Log info message using singleton logger."""
#     msg = "[INFO] " + msg
#     get_logger().info(msg)


# def log_warning(msg: str) -> None:
#     """Log warning message using singleton logger."""
#     msg = "[WARN] " + msg
#     get_logger().warning(msg)


# def log_error(msg: str) -> None:
#     """Log error message using singleton logger."""
#     msg = "[ERROR] " + msg
#     get_logger().error(msg)


# def log_critical(msg: str) -> None:
#     """Log critical message using singleton logger."""
#     msg = "[CRITICAL] " + msg
#     get_logger().critical(msg)


# def log_exception(msg: str) -> None:
#     """Log exception with stack trace using singleton logger."""
#     msg = "[EXCEPTION] " + msg
#     get_logger().exception(msg)