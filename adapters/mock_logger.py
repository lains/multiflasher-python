# coding: utf-8
"""@brief Module implementing a stub logger
"""
from typing import List

from logging import ERROR, WARNING, INFO, DEBUG
from domain.ext_adapters_interface.progressbar_interface import ProgressBarInterface, ProgressBarFactoryInterface

class MockLogger:
    """@brief Concrete implementation of a history-recording logger, used for unit test purposes"""
    def __init__(self, log_level: int= DEBUG):
        self.reset_logs()
        self.log_level = log_level

    def reset_logs(self):
        self.logs_history: List[str] = []

    def _log_as(self, type, message):
        """@brief Record a log containing @p message at a given log type
        @param level The log type (eg: ERROR, INFO etc.)
        @param message The content of the log message
        """
        if self.log_level >= type:
            self.logs_history.append(message)

    def error(self, message: str):
        self._log_as(ERROR, message)

    def warning(self, message: str):
        self._log_as(WARNING, message)

    def info(self, message: str):
        self._log_as(INFO, message)
    
    def debug(self, message: str):
        self._log_as(DEBUG, message)
