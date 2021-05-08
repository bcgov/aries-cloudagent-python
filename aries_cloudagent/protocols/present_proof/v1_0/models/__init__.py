"""Package-wide data and code."""

from os import environ

UNENCRYPTED_TAGS = environ.get("EXCH_UNENCRYPTED_TAGS", "False").upper() == "TRUE"
