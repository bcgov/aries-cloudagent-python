"""Logging utilities."""

import logging
from functools import partial, partialmethod
from typing import Optional

LOGGER = logging.getLogger(__name__)
_TRACE_LEVEL_ADDED = False


def add_logging_level(
    level_name: str, level_num: int, method_name: Optional[str] = None
) -> None:
    """Add a custom logging level to the `logging` module.

    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `level_name` becomes an attribute of the `logging` module with the value
    `level_num`.
    `methodName` becomes a convenience method for both `logging` itself
    and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`).
    If `methodName` is not specified, `levelName.lower()` is used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example:
    -------
    >>> add_logging_level('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel('TRACE')
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    References:
        - https://stackoverflow.com/a/35804945
    """
    if not method_name:
        method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError(f"{level_name} already defined in logging module")
    if hasattr(logging, method_name):
        raise AttributeError(f"{method_name} already defined in logging module")
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError(f"{method_name} already defined in logger class")

    # Add the new logging level
    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(
        logging.getLoggerClass(),
        method_name,
        partialmethod(logging.getLoggerClass().log, level_num),
    )
    setattr(logging, method_name, partial(logging.log, level_num))


def add_trace_level() -> None:
    """Add the TRACE level to the logging module safely.

    This function adds a TRACE level to the logging module if it hasn't been added yet.
    It handles the case where TRACE is already defined, avoiding duplicate additions.

    Returns:
        None
    """
    global _TRACE_LEVEL_ADDED

    if _TRACE_LEVEL_ADDED:
        return

    TRACE_LEVEL_NUM = logging.DEBUG - 5
    TRACE_LEVEL_NAME = "TRACE"
    TRACE_METHOD_NAME = "trace"

    # Check if TRACE level is already defined
    level_exists = (
        hasattr(logging, TRACE_LEVEL_NAME)
        and getattr(logging, TRACE_LEVEL_NAME) == TRACE_LEVEL_NUM
    )

    method_exists = hasattr(logging, TRACE_METHOD_NAME) and callable(
        getattr(logging, TRACE_METHOD_NAME)
    )

    if not level_exists or not method_exists:
        try:
            add_logging_level(TRACE_LEVEL_NAME, TRACE_LEVEL_NUM, TRACE_METHOD_NAME)
            LOGGER.debug("%s level added to logging module.", TRACE_LEVEL_NAME)
        except AttributeError as e:
            LOGGER.warning("%s level already exists: %s", TRACE_LEVEL_NAME, e)
    else:
        LOGGER.debug(
            "%s level is already present in the logging module.", TRACE_LEVEL_NAME
        )

    _TRACE_LEVEL_ADDED = True
