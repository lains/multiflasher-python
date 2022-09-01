# coding: utf-8
"""@brief Module declaring the interface to which must comply all concrete implementations of progress bar handlers
"""
import abc

class ProgressBarInterface(metaclass=abc.ABCMeta):
    """@brief Interface to which must comply all concrete implementations of progress bar handlers"""

    @abc.abstractmethod
    def __init__(self, name: str, min_value: int, max_value: int, show_eta: bool = False, *args, **kwargs):
        """@brief Construct a progressbar object based on its name

        @param name The name of the progress bar
        @param min_value The minimum value for progress display (corresponds to 0% progress)
        @param max_value The maximum value for progress display (corresponds to 100% progress)
        @param show_eta Should we calculate and display an estimated completion time?
        """
        raise NotImplementedError

    @abc.abstractmethod
    def __enter__(self):
        """@brief Ressource acquisition entry point"""
        raise NotImplementedError

    @abc.abstractmethod
    def __exit__(self, type, value, traceback):
        """@brief Ressource release"""
        raise NotImplementedError

    @abc.abstractmethod
    def update(self, value: int, raise_on_out_of_bounds = False):
        """Update the progressbar with a given value

        @param value The updated value
        @param raise_on_outofbounds Should we raise on out of bounds values (stricly lower than min, or strictly higher than max)? If set to no, we will saturate the value to bounds instead.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def start(self):
        """Start displaying the progressbar with 0% completion
        """
        raise NotImplementedError

    @abc.abstractmethod
    def finish(self, value: int, raise_on_out_of_bounds = False):
        """Update the progressbar with 100% completion
        """
        raise NotImplementedError

    @classmethod
    def __subclasshook__(cls, subclass):
        if cls is not ProgressBarInterface:
            return NotImplemented
        return (
            hasattr(subclass, "__enter__")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.__enter__
            )
            and hasattr(subclass, "__exit__")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.__exit__
            )
            and hasattr(subclass, "update")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.update
            )
            and hasattr(subclass, "start")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.start
            )
            and hasattr(subclass, "finish")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.finish
            )
            or NotImplemented
        )

class ProgressBarFactoryInterface(metaclass=abc.ABCMeta):
    """@brief Interface to which must comply all concrete implementations of progress bar handlers"""

    @abc.abstractstaticmethod
    def create(*args, **kwargs):
        """@brief Generate a progressbar instance

        @note All arguments are to be passed as are to the ProgressBar contructor
        """
        raise NotImplementedError

    @classmethod
    def __subclasshook__(cls, subclass):
        if cls is not ProgressBarFactoryInterface:
            return NotImplemented
        return (
            hasattr(subclass, "create")
            and callable(  # pylint: disable=consider-using-ternary
                subclass.create
            )
        )
