# coding: utf-8
"""@brief Module implementing a non-drawing progress bar
"""
from domain.ext_adapters_interface.progressbar_interface import ProgressBarInterface, ProgressBarFactoryInterface

class SilentProgressBar(ProgressBarInterface):
    """@brief Concrete implementation of ProgressBarInterface using python progressbar2"""
    def __init__(self, name: str, min_value: int, max_value: int, show_eta: bool = False, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def update(self, *args, **kwargs):
        pass
    
    def finish(self, *args, **kwargs):
        pass
    
    def start(self, *args, **kwargs):
        pass

class SilentProgressBarFactory(ProgressBarFactoryInterface):
    @staticmethod
    def create(*args, **kwargs):
        return SilentProgressBar(*args, **kwargs)