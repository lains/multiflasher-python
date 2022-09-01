# coding: utf-8
"""@brief Module providing context for flasher code
"""

from domain.ext_adapters_interface.progressbar_interface import ProgressBarInterface, ProgressBarFactoryInterface
from domain.ext_adapters_interface.hex_file_parser_interface import HexFileParser
from domain.mcu_addressing import MCULogicalAddressRange

class FlasherContext:
    """@brief Flasher context container, including handlers for UI (logger, progressbar) and for file and target access
    @note This class is used for dependency injection
    """

    def __init__(self, name: str, progressbar_factory: ProgressBarFactoryInterface, logger, firmware_file_parser: HexFileParser, target_command_executor, retries: int = 0):
        """@brief Construct a Flasher context container
        @param name The name of the context
        @param progressbar_factory A factory generating progress bar instances
        @param logger A logger to use
        @param firmware_file_parser The hex fimware instance to use to read/write firmware data
        @param target_command_executor A callback to execute commands towards the remote target embedded bootloader
        @param retries The number of retries allows on an executed command
        """
        self.progressbar_factory = progressbar_factory
        self.logger = logger
        self.firmware_file_parser = firmware_file_parser
        if not callable(target_command_executor):
            raise TypeError("target_command_executor argument is not callable")
        self._command_executor = target_command_executor
        self.retries = retries
    
    def create_progress_bar(self, name: str, min_value: int, max_value: int, *args, **kwargs) -> ProgressBarInterface:
        """@brief Construct a progress bar based on min and max values
        @param name The name of the progress bar
        @param min_value The minimum value for progress display (corresponds to 0% progress)
        @param max_value The maximum value for progress display (corresponds to 100% progress)
        @return The Progress bar that has been created
        @note All other arguments are to be passed as are to the ProgressBar contructor
        """
        return self.progressbar_factory.create(name=name, min_value=min_value, max_value=max_value, *args, **kwargs)

    def create_progress_bar_from_range(self, name: str, range: MCULogicalAddressRange, *args, **kwargs) -> ProgressBarInterface:
        """@brief Construct a progress bar from a MCULogicalAddressRange that will represent the min and max values
        @param name The name of the progress bar
        @param range The range containing the minimum and maximum values for progress display (corresponds to 0% to 100% progress)
        @note All other arguments are to be passed as are to the ProgressBar contructor
        """
        min_value = range.start_address
        max_value = range.end_address
        return self.create_progress_bar(name=name, min_value=min_value, max_value=max_value, *args, **kwargs)

    def execute_on_target(self, command):
        """@brief Execute a command on the target, using the provided target_command_executor

        @param command The command to execute

        @return An optional return value from the command
        """
        return self._command_executor(command)
