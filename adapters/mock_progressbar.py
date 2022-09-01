# coding: utf-8
"""@brief Module implementing a stub progress bar
"""
from domain.ext_adapters_interface.progressbar_interface import ProgressBarInterface, ProgressBarFactoryInterface

class MockProgressBar(ProgressBarInterface):
    """@brief Concrete implementation of ProgressBarInterface for unit test purposes"""
    def __init__(self, name: str, min_value: int, max_value: int, show_eta: bool = False, *args, **kwargs):
        self.name = name
        self.min_value = min_value
        self.max_value = max_value
        self.bar_active = False
        self.current_percent = None

    def _generate_bar_if_needed(self):
        self.bar_active = True
        self.current_percent = 0

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def update(self, value: int, raise_on_out_of_bounds = False):
        self._generate_bar_if_needed()
        if value < self.min_value or value > self.max_value:
            raise IndexError("Update value out of bounds")
        value_range = self.max_value - self.min_value
        offset_in_range = value - self.min_value
        self.current_percent = offset_in_range / value_range
    
    def finish(self):
        self._generate_bar_if_needed()
        self.bar_active = False
    
    def start(self):
        self._generate_bar_if_needed()
