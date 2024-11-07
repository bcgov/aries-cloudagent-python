"""acapy_agent package entry point."""

import logging
import os
import sys

LOGGER = logging.getLogger(__name__)


def init_debug(args):
    """Initialize debugging environment."""

    ENABLE_PTVSD = os.getenv("ENABLE_PTVSD", "").lower()
    ENABLE_PTVSD = ENABLE_PTVSD and ENABLE_PTVSD not in ("false", "0")

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_AGENT_PORT = int(os.getenv("PYDEVD_PYCHARM_AGENT_PORT", 5001))

    # --debug to use microsoft's visual studio remote debugger
    if ENABLE_PTVSD or "--debug" in args:
        DAP_HOST = os.getenv("PTVSD_HOST", None) or os.getenv("DAP_HOST", "localhost")
        DAP_PORT = int(os.getenv("PTVSD_PORT", None) or os.getenv("DAP_PORT", 5678))
        try:
            import debugpy

            debugpy.listen((DAP_HOST, DAP_PORT))
            LOGGER.info(
                f"=== Waiting for debugger to attach to {DAP_HOST}:{DAP_PORT} ==="
            )
            debugpy.wait_for_client()
        except ImportError:
            LOGGER.error("debugpy library was not found")

    if ENABLE_PYDEVD_PYCHARM or "--debug-pycharm" in args:
        try:
            import pydevd_pycharm

            LOGGER.info(
                "aca-py remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_AGENT_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_AGENT_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            LOGGER.error("pydevd_pycharm library was not found")


def run(args):
    """Execute aca-py."""
    from .commands import run_command  # noqa

    if len(args) > 1 and args[1] and args[1][0] != "-":
        command = args[1]
        args = args[2:]
    else:
        command = None
        args = args[1:]

    run_command(command, args)


def script_main():
    """Run the main function as a script for poetry."""
    main(sys.argv)


def main(args):
    """Execute default entry point."""
    init_debug(args)
    run(args)


if __name__ == "__main__":
    script_main()
