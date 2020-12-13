"""Environment utility methods."""

from pathlib import Path
from os import getenv


def storage_path(*subpaths, create: bool = False) -> Path:
    """Get the default aca-py home directory."""
    custom = getenv("ACAPY_HOME")
    if custom:
        path = Path(custom)
    else:
        path = Path.home().joinpath(".aries_cloudagent")
    if subpaths:
        path = path.joinpath(*subpaths)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path
