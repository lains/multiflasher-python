# coding: utf-8
"""@brief Module implementing a fake monitor protocol driver
"""
from typing import List

from domain.st10.monitor_comm import MonitorCommand

class MockMonitorProtocol:
    """@brief Class representing a fake communication protocol with the remote embedded monitor software
    """
    PING = b"\xb7"
    PONG = b"\x7b"
    COMMIT = 0xcafe

    def __init__(self, device, response_handler):
        """@brief Constructor
        @param device The (fake device) we read/write serial data from/to
        @param response_handler A function to which we will forward all commands, and that will emulate the remote device's formatted response
        """
        self.device = device
        if not callable(response_handler):
            raise TypeError("Provided response_handler argument is not callable")
        self.response_handler = response_handler
        self.commands_history: List[MonitorCommand] = []

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        pass

    def execute(self, command: MonitorCommand):
        """@brief Request execution of a specific command on the remote embedded monitor software
        @param command The command to execute
        @return The outcome of the command (can be None, a boolean or the instance of an object encapsulating data)
        """
        assert isinstance(command, MonitorCommand)  # command provided as argument should implement the MonitorCommand interface
        self.commands_history.append(command)
        return self.response_handler(command)
