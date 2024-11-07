"""Logging Configurator for aca-py agent."""

import configparser
import io
import logging
import logging.config
import os
import sys
from importlib import resources
from logging.config import (
    _clearExistingHandlers,
    _create_formatters,
    _install_handlers,
    _install_loggers,
    dictConfigClass,
)
from typing import Optional

import yaml
from pythonjsonlogger.json import JsonFormatter

from ...config.settings import Settings
from ...version import __version__
from ..banner import Banner
from .base import (
    DEFAULT_LOGGING_CONFIG_PATH_INI,
    DEFAULT_MULTITENANT_LOGGING_CONFIG_PATH_INI,
    LOG_FORMAT_FILE_ALIAS_PATTERN,
)
from .filters import ContextFilter
from .timed_rotating_file_multi_process_handler import (
    TimedRotatingFileMultiProcessHandler,
)
from .utils import add_trace_level


# Add TRACE level to logging before any configuration
add_trace_level()


def load_resource(path: str, encoding: Optional[str] = None):
    """Open a resource file located in a python package or the local filesystem.

    Args:
        path (str): The resource path in the form of `dir/file` or `package:dir/file`
        encoding (str, optional): The encoding to use when reading the resource file.
            Defaults to None.

    Returns:
        file-like object: A file-like object representing the resource
    """
    components = path.rsplit(":", 1)
    try:
        if len(components) == 1:
            # Local filesystem resource
            return open(components[0], encoding=encoding)
        else:
            # Package resource
            package, resource = components
            bstream = resources.files(package).joinpath(resource).open("rb")
            if encoding:
                return io.TextIOWrapper(bstream, encoding=encoding)
            return bstream
    except IOError:
        pass


def dictConfig(config, new_file_path=None):
    """Custom dictConfig, https://github.com/python/cpython/blob/main/Lib/logging/config.py."""
    if new_file_path:
        config["handlers"]["rotating_file"]["filename"] = f"{new_file_path}"
    dictConfigClass(config).configure()


def fileConfig(
    fname,
    new_file_path=None,
    defaults=None,
    disable_existing_loggers=True,
    encoding=None,
):
    """Custom fileConfig to update filepath in ConfigParser file handler section."""
    if isinstance(fname, str):
        if not os.path.exists(fname):
            raise FileNotFoundError(f"{fname} doesn't exist")
        elif not os.path.getsize(fname):
            raise RuntimeError(f"{fname} is an empty file")

    if isinstance(fname, configparser.RawConfigParser):
        cp = fname
    else:
        try:
            cp = configparser.ConfigParser(defaults)
            if hasattr(fname, "readline"):
                cp.read_file(fname)
            else:
                encoding = io.text_encoding(encoding)
                cp.read(fname, encoding=encoding)
        except configparser.ParsingError as e:
            raise RuntimeError(f"{fname} is invalid: {e}")

    if new_file_path and cp.has_section("handler_timed_file_handler"):
        cp.set(
            "handler_timed_file_handler",
            "args",
            str(
                (
                    f"{new_file_path}",
                    "d",
                    7,
                    1,
                )
            ),
        )

    formatters = _create_formatters(cp)
    with logging._lock:
        _clearExistingHandlers()
        handlers = _install_handlers(cp, formatters)
        _install_loggers(cp, handlers, disable_existing_loggers)


class LoggingConfigurator:
    """Utility class used to configure logging and print an informative start banner."""

    default_config_path_ini = DEFAULT_LOGGING_CONFIG_PATH_INI
    default_multitenant_config_path_ini = DEFAULT_MULTITENANT_LOGGING_CONFIG_PATH_INI

    @classmethod
    def configure(
        cls,
        log_config_path: Optional[str] = None,
        log_level: Optional[str] = None,
        log_file: Optional[str] = None,
        multitenant: bool = False,
    ):
        """Configure logger.

        :param logging_config_path: str: (Default value = None) Optional path to
            custom logging config

        :param log_level: str: (Default value = None)

        :param log_file: str: (Default value = None) Optional file name to write logs to

        :param multitenant: bool: (Default value = False) Optional flag if multitenant is
            enabled
        """

        write_to_log_file = log_file is not None or log_file == ""

        if multitenant:
            # The default logging config for multi-tenant mode specifies a log file
            # location if --log-file is specified on startup and a config file is not.
            # When all else fails, the default single-tenant config file is used.
            if not log_config_path:
                log_config_path = (
                    cls.default_multitenant_config_path_ini
                    if write_to_log_file
                    else cls.default_config_path_ini
                )

            cls._configure_multitenant_logging(
                log_config_path=log_config_path,
                log_level=log_level,
                log_file=log_file,
            )
        else:
            # The default config for single-tenant mode does not specify a log file
            # location. This is a check that requires a log file path to be provided if
            # --log-file is specified on startup and a config file is not.
            if not log_config_path and write_to_log_file and not log_file:
                raise ValueError(
                    "log_file (--log-file) must be provided in single-tenant mode "
                    "using the default config since a log file path is not set."
                )

            cls._configure_logging(
                log_config_path=log_config_path or cls.default_config_path_ini,
                log_level=log_level,
                log_file=log_file,
            )

    @classmethod
    def _configure_logging(cls, log_config_path, log_level, log_file):
        # Setup log config and log file if provided
        cls._setup_log_config_file(log_config_path, log_file)

        # Set custom file handler
        if log_file:
            logging.root.handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

        # Set custom log level
        if log_level:
            logging.root.setLevel(log_level.upper())

    @classmethod
    def _configure_multitenant_logging(cls, log_config_path, log_level, log_file):
        # Setup log config and log file if provided
        cls._setup_log_config_file(log_config_path, log_file)

        # Set custom file handler(s)
        ############################
        # Step through each root handler and find any TimedRotatingFileMultiProcessHandler
        any_file_handlers_set = filter(
            lambda handler: isinstance(handler, TimedRotatingFileMultiProcessHandler),
            logging.root.handlers,
        )

        # Default context filter adds wallet_id to log records
        log_filter = ContextFilter()
        if (not any_file_handlers_set) and log_file:
            file_path = os.path.join(
                os.path.dirname(os.path.realpath(__file__)).replace(
                    "acapy_agent/config", ""
                ),
                log_file,
            )
            # By default the timed rotated file handler will have:
            # interval=7, when=d and backupCount=1
            timed_file_handler = TimedRotatingFileMultiProcessHandler(
                filename=file_path,
                interval=7,
                when="d",
                backupCount=1,
            )
            timed_file_handler.addFilter(log_filter)
            # By default this will be set up.
            timed_file_handler.setFormatter(JsonFormatter(LOG_FORMAT_FILE_ALIAS_PATTERN))
            logging.root.handlers.append(timed_file_handler)

        else:
            # Setup context filters for multitenant mode
            for handler in logging.root.handlers:
                if isinstance(handler, TimedRotatingFileMultiProcessHandler):
                    log_formater = handler.formatter._fmt
                    # Set Json formatter for rotated file handler which cannot be set with
                    # config file.
                    # By default this will be set up.
                    handler.setFormatter(JsonFormatter(log_formater))
                # Add context filter to handlers
                handler.addFilter(log_filter)

                # Sets a custom log level
                if log_level:
                    handler.setLevel(log_level.upper())

        # Set custom log level
        if log_level:
            logging.root.setLevel(log_level.upper())

    @classmethod
    def _setup_log_config_file(cls, log_config_path, log_file):
        log_config, is_dict_config = cls._load_log_config(log_config_path)

        # Setup config
        if not log_config:
            logging.basicConfig(level=logging.WARNING)
            logging.root.warning(f"Logging config file not found: {log_config_path}")
        elif is_dict_config:
            dictConfig(log_config, new_file_path=log_file or None)
        else:
            with log_config:
                # The default log_file location is set here
                # if one is not provided in the startup params
                fileConfig(
                    log_config,
                    new_file_path=log_file or None,
                    disable_existing_loggers=False,
                )

    @classmethod
    def _load_log_config(cls, log_config_path):
        if ".yml" in log_config_path or ".yaml" in log_config_path:
            with open(log_config_path, "r") as stream:
                return yaml.safe_load(stream), True
        return load_resource(log_config_path, "utf-8"), False

    @classmethod
    def print_banner(
        cls,
        agent_label,
        inbound_transports,
        outbound_transports,
        public_did,
        admin_server=None,
        banner_length=40,
        border_character=":",
    ):
        """Print a startup banner describing the configuration.

        Args:
            agent_label: Agent Label
            inbound_transports: Configured inbound transports
            outbound_transports: Configured outbound transports
            admin_server: Admin server info
            public_did: Public DID
            banner_length: (Default value = 40) Length of the banner
            border_character: (Default value = ":") Character to use in banner
            border
        """
        print()
        with Banner(border=border_character, length=banner_length) as banner:
            # Title
            banner.title(agent_label or "ACA")
            # Inbound transports
            if inbound_transports:
                banner.subtitle("Inbound Transports")
                internal_in_transports = [
                    f"{transport.scheme}://{transport.host}:{transport.port}"
                    for transport in inbound_transports.values()
                    if not transport.is_external
                ]
                if internal_in_transports:
                    banner.list(internal_in_transports)
                external_in_transports = [
                    f"{transport.scheme}://{transport.host}:{transport.port}"
                    for transport in inbound_transports.values()
                    if transport.is_external
                ]
                if external_in_transports:
                    banner.subtitle("  External Plugin")
                    banner.list(external_in_transports)

            # Outbound transports
            if outbound_transports:
                banner.subtitle("Outbound Transports")
                internal_schemes = set().union(
                    *(
                        transport.schemes
                        for transport in outbound_transports.values()
                        if not transport.is_external
                    )
                )
                if internal_schemes:
                    banner.list([f"{scheme}" for scheme in sorted(internal_schemes)])

                external_schemes = set().union(
                    *(
                        transport.schemes
                        for transport in outbound_transports.values()
                        if transport.is_external
                    )
                )
                if external_schemes:
                    banner.subtitle("  External Plugin")
                    banner.list([f"{scheme}" for scheme in sorted(external_schemes)])

            # DID info
            if public_did:
                banner.subtitle("Public DID Information")
                banner.list([f"DID: {public_did}"])

            # Admin server info
            banner.subtitle("Administration API")
            banner.list(
                [f"http://{admin_server.host}:{admin_server.port}"]
                if admin_server
                else ["not enabled"]
            )

            banner.version(__version__)

        print()
        print("Listening...")
        print()

    @classmethod
    def print_notices(cls, settings: Settings):
        """Print notices and warnings."""
        with Banner(border=":", length=80, file=sys.stderr) as banner:
            if settings.get("wallet.type", "in_memory").lower() == "indy":
                banner.centered("⚠ DEPRECATION NOTICE: ⚠")
                banner.hr()
                banner.print(
                    "The Indy wallet type is deprecated, use Askar instead; see: "
                    "https://aca-py.org/main/deploying/IndySDKtoAskarMigration/",
                )
                banner.hr()
            if not settings.get("transport.disabled"):
                banner.centered("⚠ DEPRECATION NOTICE: ⚠")
                banner.hr()
                banner.print(
                    "Receiving a core DIDComm protocol with the "
                    "`did:sov:BzCbsNYhMrjHiqZDTUASHg;spec` prefix is deprecated. "
                    "All parties sending this prefix should be notified that support "
                    "for receiving such messages will be removed in a future release. "
                    "Use https://didcomm.org/ instead."
                )
                banner.hr()
                banner.print(
                    "Aries RFC 0160: Connection Protocol is deprecated and "
                    "support will be removed in a future release; "
                    "use RFC 0023: DID Exchange instead."
                )
                banner.hr()
                banner.print(
                    "Aries RFC 0036: Issue Credential 1.0 is deprecated "
                    "and support will be removed in a future release; "
                    "use RFC 0453: Issue Credential 2.0 instead."
                )
                banner.hr()
                banner.print(
                    "Aries RFC 0037: Present Proof 1.0 is deprecated "
                    "and support will be removed in a future release; "
                    "use RFC 0454: Present Proof 2.0 instead."
                )
        print()
