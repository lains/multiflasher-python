# coding: utf-8
"""@brief Module implementing a nice-looking textual progress bar using python progressbar2
"""
import progressbar
from domain.ext_adapters_interface.progressbar_interface import ProgressBarInterface, ProgressBarFactoryInterface

class ProgressBar2(ProgressBarInterface):
    """@brief Concrete implementation of ProgressBarInterface using python progressbar2"""
    def __init__(self, name: str, min_value: int, max_value: int, show_eta: bool = False, *args, **kwargs):
        self.widgets=[name, progressbar.GranularBar()]
        if show_eta:
            self.widgets += [" (", progressbar.AdaptiveETA(), ") " ]
        self.min_value = min_value
        self.max_value = max_value
        self.bar = None

    def _generate_bar_if_needed(self):
        if self.bar is None:
            self.bar = progressbar.ProgressBar(min_value=self.min_value, max_value=self.max_value, widgets=self.widgets)

    def __enter__(self):
        self._generate_bar_if_needed()
        return self

    def __exit__(self, type, value, traceback):
        pass

    def update(self, value: int, raise_on_out_of_bounds = False):
        self._generate_bar_if_needed()
        def raise_exception(message):
            raise IndexError(message)
        
        if raise_on_out_of_bounds:
            raise_if_requested = raise_exception
        else:
            raise_if_requested = lambda *args: None

        if value < self.min_value:
            raise_if_requested("Value " + str(value) + " too low (minimum " + str(self.min_value))
            value = self.min_value
        if value > self.max_value:
            raise_if_requested("Value " + str(value) + " too high (maximum " + str(self.max_value))
            value = self.max_value
        self.bar.update(value)
    
    def finish(self):
        self._generate_bar_if_needed()
        self.bar.finish()
    
    def start(self):
        self._generate_bar_if_needed()
        self.update(self.min_value)

class ProgressBar2Factory(ProgressBarFactoryInterface):
    @staticmethod
    def create(*args, **kwargs):
        return ProgressBar2(*args, **kwargs)