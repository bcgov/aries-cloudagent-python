"""Command line option parsing."""

import abc
from os import environ

from configargparse import ArgumentParser, Namespace, YAMLConfigFileParser
from typing import Type

from .error import ArgsParseError
from .util import BoundedInt, ByteSize
from ..utils.tracing import trace_event

CAT_PROVISION = "general"
CAT_START = "start"


class ArgumentGroup(abc.ABC):
    """A class representing a group of related command line arguments."""

    GROUP_NAME = None

    @abc.abstractmethod
    def add_arguments(self, parser: ArgumentParser):
        """Add arguments to the provided argument parser."""

    @abc.abstractmethod
    def get_settings(self, args: Namespace) -> dict:
        """Extract settings from the parsed arguments."""


class group:
    """Decorator for registering argument groups."""

    _registered = []

    def __init__(self, *categories):
        """Initialize the decorator."""
        self.categories = tuple(categories)

    def __call__(self, group_cls: ArgumentGroup):
        """Register a class in the given categories."""
        setattr(group_cls, "CATEGORIES", self.categories)
        self._registered.append((self.categories, group_cls))
        return group_cls

    @classmethod
    def get_registered(cls, category: str = None):
        """Fetch the set of registered classes in a category."""
        return (
            grp
            for (cats, grp) in cls._registered
            if category is None or category in cats
        )


def create_argument_parser(*, prog: str = None):
    """Create am instance of an arg parser, force yaml format for external config."""
    return ArgumentParser(config_file_parser_class=YAMLConfigFileParser, prog=prog)


def load_argument_groups(parser: ArgumentParser, *groups: Type[ArgumentGroup]):
    """Log a set of argument groups into a parser.

    Returns:
        A callable to convert loaded arguments into a settings dictionary

    """
    group_inst = []
    for group in groups:
        g_parser = parser.add_argument_group(group.GROUP_NAME)
        inst = group()
        inst.add_arguments(g_parser)
        group_inst.append(inst)

    def get_settings(args: Namespace):
        settings = {}
        try:
            for group in group_inst:
                settings.update(group.get_settings(args))
        except ArgsParseError as e:
            # this is defined to exit or raise an exception and is
            # consistent with an error being raised while the arguments
            # are being parsed
            parser.error(str(e))
        return settings

    return get_settings


@group(CAT_START)
class AdminGroup(ArgumentGroup):
    """Admin server settings."""

    GROUP_NAME = "Admin"

    def add_arguments(self, parser: ArgumentParser):
        """Add admin-specific command line arguments to the parser."""
        parser.add_argument(
            "--admin",
            type=str,
            nargs=2,
            metavar=("<host>", "<port>"),
            env_var="ACAPY_ADMIN",
            help="Specify the host and port on which to run the administrative server.\
            If not provided, no admin server is made available.",
        )
        parser.add_argument(
            "--admin-api-key",
            type=str,
            metavar="<api-key>",
            env_var="ACAPY_ADMIN_API_KEY",
            help="Protect all admin endpoints with the provided API key.\
            API clients (e.g. the controller) must pass the key in the HTTP\
            header using 'X-API-Key: <api key>'. Either this parameter or the\
            '--admin-insecure-mode' parameter MUST be specified.",
        )
        parser.add_argument(
            "--admin-insecure-mode",
            action="store_true",
            env_var="ACAPY_ADMIN_INSECURE_MODE",
            help="Run the admin web server in insecure mode. DO NOT USE FOR\
            PRODUCTION DEPLOYMENTS. The admin server will be publicly available\
            to anyone who has access to the interface. Either this parameter or\
            the '--api-key' parameter MUST be specified.",
        )
        parser.add_argument(
            "--no-receive-invites",
            action="store_true",
            env_var="ACAPY_NO_RECEIVE_INVITES",
            help="Prevents an agent from receiving invites by removing the\
            '/connections/receive-invite' route from the administrative\
            interface. Default: false.",
        )
        parser.add_argument(
            "--help-link",
            type=str,
            metavar="<help-url>",
            env_var="ACAPY_HELP_LINK",
            help="A URL to an administrative interface help web page that a controller\
            user interface can get from the agent and provide as a link to users.",
        )
        parser.add_argument(
            "--webhook-url",
            action="append",
            metavar="<url#api_key>",
            env_var="ACAPY_WEBHOOK_URL",
            help="Send webhooks containing internal state changes to the specified\
            URL. Optional API key to be passed in the request body can be appended using\
            a hash separator [#]. This is useful for a controller to monitor agent events\
            and respond to those events using the admin API. If not specified, \
            webhooks are not published by the agent.",
        )

    def get_settings(self, args: Namespace):
        """Extract admin settings."""
        settings = {}
        if args.admin:
            admin_api_key = args.admin_api_key
            admin_insecure_mode = args.admin_insecure_mode

            if (admin_api_key and admin_insecure_mode) or not (
                admin_api_key or admin_insecure_mode
            ):
                raise ArgsParseError(
                    "Either --admin-api-key or --admin-insecure-mode "
                    + "must be set but not both."
                )

            settings["admin.admin_api_key"] = admin_api_key
            settings["admin.admin_insecure_mode"] = admin_insecure_mode

            settings["admin.enabled"] = True
            settings["admin.host"] = args.admin[0]
            settings["admin.port"] = args.admin[1]
            if args.help_link:
                settings["admin.help_link"] = args.help_link
            if args.no_receive_invites:
                settings["admin.no_receive_invites"] = True
            hook_urls = list(args.webhook_url) if args.webhook_url else []
            hook_url = environ.get("WEBHOOK_URL")
            if hook_url:
                hook_urls.append(hook_url)
            settings["admin.webhook_urls"] = hook_urls
        return settings


@group(CAT_START)
class DebugGroup(ArgumentGroup):
    """Debug settings."""

    GROUP_NAME = "Debug"

    def add_arguments(self, parser: ArgumentParser):
        """Add debug command line arguments to the parser."""
        parser.add_argument(
            "--debug",
            action="store_true",
            env_var="ACAPY_DEBUG",
            help="Enables a remote debugging service that can be accessed\
            using ptvsd for Visual Studio Code. The framework will wait\
            for the debugger to connect at start-up. Default: false.",
        )
        parser.add_argument(
            "--debug-seed",
            dest="debug_seed",
            type=str,
            metavar="<debug-did-seed>",
            env_var="ACAPY_DEBUG_SEED",
            help="Specify the debug seed to use.",
        )
        parser.add_argument(
            "--debug-connections",
            action="store_true",
            env_var="ACAPY_DEBUG_CONNECTIONS",
            help="Enable additional logging around connections. Default: false.",
        )
        parser.add_argument(
            "--debug-credentials",
            action="store_true",
            env_var="ACAPY_DEBUG_CREDENTIALS",
            help="Enable additional logging around credential exchanges.\
            Default: false.",
        )
        parser.add_argument(
            "--debug-presentations",
            action="store_true",
            env_var="ACAPY_DEBUG_PRESENTATIONS",
            help="Enable additional logging around presentation exchanges.\
            Default: false.",
        )
        parser.add_argument(
            "--invite",
            action="store_true",
            env_var="ACAPY_INVITE",
            help="After startup, generate and print a new out-of-band connection invitation\
            URL. Default: false.",
        )
        parser.add_argument(
            "--connections-invite",
            action="store_true",
            env_var="ACAPY_CONNECTIONS_INVITE",
            help="After startup, generate and print a new connections protocol \
            style invitation URL. Default: false.",
        )
        parser.add_argument(
            "--invite-label",
            dest="invite_label",
            type=str,
            metavar="<label>",
            env_var="ACAPY_INVITE_LABEL",
            help="Specify the label of the generated invitation.",
        )
        parser.add_argument(
            "--invite-multi-use",
            action="store_true",
            env_var="ACAPY_INVITE_MULTI_USE",
            help="Flag specifying the generated invite should be multi-use.",
        )
        parser.add_argument(
            "--invite-public",
            action="store_true",
            env_var="ACAPY_INVITE_PUBLIC",
            help="Flag specifying the generated invite should be public.",
        )
        parser.add_argument(
            "--invite-metadata-json",
            type=str,
            metavar="<metadata-json>",
            env_var="ACAPY_INVITE_METADATA_JSON",
            help="Add metadata json to invitation created with --invite argument.",
        )
        parser.add_argument(
            "--test-suite-endpoint",
            type=str,
            metavar="<endpoint>",
            env_var="ACAPY_TEST_SUITE_ENDPOINT",
            help="URL endpoint for sending messages to the test suite agent.",
        )

        parser.add_argument(
            "--auto-accept-invites",
            action="store_true",
            env_var="ACAPY_AUTO_ACCEPT_INVITES",
            help="Automatically accept invites without firing a webhook event or\
            waiting for an admin request. Default: false.",
        )
        parser.add_argument(
            "--auto-accept-requests",
            action="store_true",
            env_var="ACAPY_AUTO_ACCEPT_REQUESTS",
            help="Automatically accept connection requests without firing\
            a webhook event or waiting for an admin request. Default: false.",
        )
        parser.add_argument(
            "--auto-respond-messages",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_MESSAGES",
            help="Automatically respond to basic messages indicating the message was\
            received. Default: false.",
        )
        parser.add_argument(
            "--auto-respond-credential-proposal",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_CREDENTIAL_PROPOSAL",
            help="Auto-respond to credential proposals with corresponding "
            + "credential offers",
        )
        parser.add_argument(
            "--auto-respond-credential-offer",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_CREDENTIAL_OFFER",
            help="Automatically respond to Indy credential offers with a credential\
            request. Default: false",
        )
        parser.add_argument(
            "--auto-respond-credential-request",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_CREDENTIAL_REQUEST",
            help="Auto-respond to credential requests with corresponding credentials",
        )
        parser.add_argument(
            "--auto-respond-presentation-proposal",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_PRESENTATION_PROPOSAL",
            help="Auto-respond to presentation proposals with corresponding "
            + "presentation requests",
        )
        parser.add_argument(
            "--auto-respond-presentation-request",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST",
            help="Automatically respond to Indy presentation requests with a\
            constructed presentation if a corresponding credential can be retrieved\
            for every referent in the presentation request. Default: false.",
        )
        parser.add_argument(
            "--auto-store-credential",
            action="store_true",
            env_var="ACAPY_AUTO_STORE_CREDENTIAL",
            help="Automatically store an issued credential upon receipt.\
            Default: false.",
        )
        parser.add_argument(
            "--auto-verify-presentation",
            action="store_true",
            env_var="ACAPY_AUTO_VERIFY_PRESENTATION",
            help="Automatically verify a presentation when it is received.\
            Default: false.",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract debug settings."""
        settings = {}
        if args.debug:
            settings["debug.enabled"] = True
        if args.debug_connections:
            settings["debug.connections"] = True
        if args.debug_credentials:
            settings["debug.credentials"] = True
        if args.debug_presentations:
            settings["debug.presentations"] = True
        if args.debug_seed:
            settings["debug.seed"] = args.debug_seed
        if args.invite:
            settings["debug.print_invitation"] = True
        if args.connections_invite:
            settings["debug.print_connections_invitation"] = True
        if args.invite_label:
            settings["debug.invite_label"] = args.invite_label
        if args.invite_multi_use:
            settings["debug.invite_multi_use"] = True
        if args.invite_public:
            settings["debug.invite_public"] = True
        if args.invite_metadata_json:
            settings["debug.invite_metadata_json"] = args.invite_metadata_json
        if args.test_suite_endpoint:
            settings["debug.test_suite_endpoint"] = args.test_suite_endpoint

        if args.auto_respond_credential_proposal:
            settings["debug.auto_respond_credential_proposal"] = True
        if args.auto_respond_credential_offer:
            settings["debug.auto_respond_credential_offer"] = True
        if args.auto_respond_credential_request:
            settings["debug.auto_respond_credential_request"] = True
        if args.auto_respond_presentation_proposal:
            settings["debug.auto_respond_presentation_proposal"] = True
        if args.auto_respond_presentation_request:
            settings["debug.auto_respond_presentation_request"] = True
        if args.auto_store_credential:
            settings["debug.auto_store_credential"] = True
        if args.auto_verify_presentation:
            settings["debug.auto_verify_presentation"] = True
        if args.auto_accept_invites:
            settings["debug.auto_accept_invites"] = True
        if args.auto_accept_requests:
            settings["debug.auto_accept_requests"] = True
        if args.auto_respond_messages:
            settings["debug.auto_respond_messages"] = True
        return settings


@group(CAT_PROVISION, CAT_START)
class GeneralGroup(ArgumentGroup):
    """General settings."""

    GROUP_NAME = "General"

    def add_arguments(self, parser: ArgumentParser):
        """Add general command line arguments to the parser."""
        parser.add_argument(
            "--arg-file",
            is_config_file=True,
            help="Load aca-py arguments from the specified file.  Note that\
            this file *must* be in YAML format.",
        )
        parser.add_argument(
            "--plugin",
            dest="external_plugins",
            type=str,
            action="append",
            required=False,
            metavar="<module>",
            env_var="ACAPY_PLUGIN",
            help="Load <module> as external plugin module. Multiple\
            instances of this parameter can be specified.",
        )
        parser.add_argument(
            "--storage-type",
            type=str,
            metavar="<storage-type>",
            env_var="ACAPY_STORAGE_TYPE",
            help="Specifies the type of storage provider to use for the internal\
            storage engine. This storage interface is used to store internal state.\
            Supported internal storage types are 'basic' (memory)\
            and 'indy'.  The default (if not specified) is 'indy' if the wallet type\
            is set to 'indy', otherwise 'basic'.",
        )
        parser.add_argument(
            "-e",
            "--endpoint",
            type=str,
            nargs="+",
            metavar="<endpoint>",
            env_var="ACAPY_ENDPOINT",
            help="Specifies the endpoints to put into DIDDocs\
            to inform other agents of where they should send messages destined\
            for this agent. Each endpoint could be one of the specified inbound\
            transports for this agent, or the endpoint could be that of\
            another agent (e.g. 'https://example.com/agent-endpoint') if the\
            routing of messages to this agent by a mediator is configured.\
            The first endpoint specified will be used in invitations.\
            The endpoints are used in the formation of a connection\
            with another agent.",
        )
        parser.add_argument(
            "--profile-endpoint",
            type=str,
            metavar="<profile_endpoint>",
            env_var="ACAPY_PROFILE_ENDPOINT",
            help="Specifies the profile endpoint for the (public) DID.",
        )
        parser.add_argument(
            "--read-only-ledger",
            action="store_true",
            env_var="ACAPY_READ_ONLY_LEDGER",
            help="Sets ledger to read-only to prevent updates.\
            Default: false.",
        )
        parser.add_argument(
            "--tails-server-base-url",
            type=str,
            metavar="<tails-server-base-url>",
            env_var="ACAPY_TAILS_SERVER_BASE_URL",
            help="Sets the base url of the tails server in use.",
        )
        parser.add_argument(
            "--tails-server-upload-url",
            type=str,
            metavar="<tails-server-upload-url>",
            env_var="ACAPY_TAILS_SERVER_UPLOAD_URL",
            help="Sets the base url of the tails server for upload, defaulting to the\
            tails server base url.",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract general settings."""
        settings = {}
        if args.external_plugins:
            settings["external_plugins"] = args.external_plugins
        if args.storage_type:
            settings["storage_type"] = args.storage_type

        if args.endpoint:
            settings["default_endpoint"] = args.endpoint[0]
            settings["additional_endpoints"] = args.endpoint[1:]
        else:
            raise ArgsParseError("-e/--endpoint is required")
        if args.profile_endpoint:
            settings["profile_endpoint"] = args.profile_endpoint

        if args.read_only_ledger:
            settings["read_only_ledger"] = True
        if args.tails_server_base_url:
            settings["tails_server_base_url"] = args.tails_server_base_url
            settings["tails_server_upload_url"] = args.tails_server_base_url
        if args.tails_server_upload_url:
            settings["tails_server_upload_url"] = args.tails_server_upload_url
        return settings


@group(CAT_START, CAT_PROVISION)
class LedgerGroup(ArgumentGroup):
    """Ledger settings."""

    GROUP_NAME = "Ledger"

    def add_arguments(self, parser: ArgumentParser):
        """Add ledger-specific command line arguments to the parser."""
        parser.add_argument(
            "--ledger-pool-name",
            type=str,
            metavar="<ledger-pool-name>",
            env_var="ACAPY_LEDGER_POOL_NAME",
            help="Specifies the name of the indy pool to be opened.\
            This is useful if you have multiple pool configurations.",
        )
        parser.add_argument(
            "--genesis-transactions",
            type=str,
            dest="genesis_transactions",
            metavar="<genesis-transactions>",
            env_var="ACAPY_GENESIS_TRANSACTIONS",
            help='Specifies the genesis transactions to use to connect to\
            an Hyperledger Indy ledger. The transactions are provided as string\
            of JSON e.g. \'{"reqSignature":{},"txn":{"data":{"d... <snip>\'',
        )
        parser.add_argument(
            "--genesis-file",
            type=str,
            dest="genesis_file",
            metavar="<genesis-file>",
            env_var="ACAPY_GENESIS_FILE",
            help="Specifies a local file from which to read the genesis transactions.",
        )
        parser.add_argument(
            "--genesis-url",
            type=str,
            dest="genesis_url",
            metavar="<genesis-url>",
            env_var="ACAPY_GENESIS_URL",
            help="Specifies the url from which to download the genesis\
            transactions. For example, if you are using 'von-network',\
            the URL might be 'http://localhost:9000/genesis'.\
            Genesis transactions URLs are available for the Sovrin test/main networks.",
        )
        parser.add_argument(
            "--no-ledger",
            action="store_true",
            env_var="ACAPY_NO_LEDGER",
            help="Specifies that aca-py will run with no ledger configured.\
            This must be set if running in no-ledger mode.  Overrides any\
            specified ledger or genesis configurations.  Default: false.",
        )
        parser.add_argument(
            "--ledger-keepalive",
            default=5,
            type=BoundedInt(min=5),
            env_var="ACAPY_LEDGER_KEEP_ALIVE",
            help="Specifies how many seconds to keep the ledger open. Default: 5",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract ledger settings."""
        settings = {}
        if args.no_ledger:
            settings["ledger.disabled"] = True
        else:
            if args.genesis_url:
                settings["ledger.genesis_url"] = args.genesis_url
            elif args.genesis_file:
                settings["ledger.genesis_file"] = args.genesis_file
            elif args.genesis_transactions:
                settings["ledger.genesis_transactions"] = args.genesis_transactions
            else:
                raise ArgsParseError(
                    "One of --genesis-url --genesis-file or --genesis-transactions "
                    + "must be specified (unless --no-ledger is specified to "
                    + "explicitly configure aca-py to run with no ledger)."
                )
            if args.ledger_pool_name:
                settings["ledger.pool_name"] = args.ledger_pool_name
            if args.ledger_keepalive:
                settings["ledger.keepalive"] = args.ledger_keepalive

        return settings


@group(CAT_PROVISION, CAT_START)
class LoggingGroup(ArgumentGroup):
    """Logging settings."""

    GROUP_NAME = "Logging"

    def add_arguments(self, parser: ArgumentParser):
        """Add logging-specific command line arguments to the parser."""
        parser.add_argument(
            "--log-config",
            dest="log_config",
            type=str,
            metavar="<path-to-config>",
            default=None,
            env_var="ACAPY_LOG_CONFIG",
            help="Specifies a custom logging configuration file",
        )
        parser.add_argument(
            "--log-file",
            dest="log_file",
            type=str,
            metavar="<log-file>",
            default=None,
            env_var="ACAPY_LOG_FILE",
            help="Overrides the output destination for the root logger (as defined\
            by the log config file) to the named <log-file>.",
        )
        parser.add_argument(
            "--log-level",
            dest="log_level",
            type=str,
            metavar="<log-level>",
            default=None,
            env_var="ACAPY_LOG_LEVEL",
            help="Specifies a custom logging level as one of:\
            ('debug', 'info', 'warning', 'error', 'critical')",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract logging settings."""
        settings = {}
        if args.log_config:
            settings["log.config"] = args.log_config
        if args.log_file:
            settings["log.file"] = args.log_file
        if args.log_level:
            settings["log.level"] = args.log_level
        return settings


@group(CAT_START)
class ProtocolGroup(ArgumentGroup):
    """Protocol settings."""

    GROUP_NAME = "Protocol"

    def add_arguments(self, parser: ArgumentParser):
        """Add protocol-specific command line arguments to the parser."""
        parser.add_argument(
            "--aip-version",
            type=BoundedInt(1, 2),
            default=1,
            env_var="ACAPY_AIP_VERSION",
            help="Set the Aries Interop Profile compatibility version (default 1).",
        )
        parser.add_argument(
            "--auto-ping-connection",
            action="store_true",
            env_var="ACAPY_AUTO_PING_CONNECTION",
            help="Automatically send a trust ping immediately after a\
            connection response is accepted. Some agents require this before\
            marking a connection as 'active'. Default: false.",
        )
        parser.add_argument(
            "--invite-base-url",
            type=str,
            metavar="<base-url>",
            env_var="ACAPY_INVITE_BASE_URL",
            help="Base URL to use when formatting connection invitations in URL format.",
        )
        parser.add_argument(
            "--monitor-ping",
            action="store_true",
            env_var="ACAPY_MONITOR_PING",
            help="Send a webhook when a ping is sent or received.",
        )
        parser.add_argument(
            "--public-invites",
            action="store_true",
            env_var="ACAPY_PUBLIC_INVITES",
            help="Send invitations out, and receive connection requests,\
            using the public DID for the agent. Default: false.",
        )
        parser.add_argument(
            "--timing",
            action="store_true",
            env_var="ACAPY_TIMING",
            help="Include timing information in response messages.",
        )
        parser.add_argument(
            "--timing-log",
            type=str,
            metavar="<log-path>",
            env_var="ACAPY_TIMING_LOG",
            help="Write timing information to a given log file.",
        )
        parser.add_argument(
            "--trace",
            action="store_true",
            env_var="ACAPY_TRACE",
            help="Generate tracing events.",
        )
        parser.add_argument(
            "--trace-target",
            type=str,
            metavar="<trace-target>",
            env_var="ACAPY_TRACE_TARGET",
            help='Target for trace events ("log", "message", or http endpoint).',
        )
        parser.add_argument(
            "--trace-tag",
            type=str,
            metavar="<trace-tag>",
            env_var="ACAPY_TRACE_TAG",
            help="Tag to be included when logging events.",
        )
        parser.add_argument(
            "--trace-label",
            type=str,
            metavar="<trace-label>",
            env_var="ACAPY_TRACE_LABEL",
            help="Label (agent name) used logging events.",
        )
        parser.add_argument(
            "--preserve-exchange-records",
            action="store_true",
            env_var="ACAPY_PRESERVE_EXCHANGE_RECORDS",
            help="Keep credential exchange records after exchange has completed.",
        )
        parser.add_argument(
            "--exch-use-unencrypted-tags",
            action="store_true",
            env_var="ACAPY_EXCH_USE_UNENCRYPTED_TAGS",
            help="Store tags for exchange protocols (credential and presentation)\
            using unencrypted rather than encrypted tags",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Get protocol settings."""
        settings = {}
        settings["aip_version"] = args.aip_version
        if args.auto_ping_connection:
            settings["auto_ping_connection"] = True
        if args.invite_base_url:
            settings["invite_base_url"] = args.invite_base_url
        if args.monitor_ping:
            settings["debug.monitor_ping"] = args.monitor_ping
        if args.public_invites:
            settings["public_invites"] = True
        if args.timing:
            settings["timing.enabled"] = True
        if args.timing_log:
            settings["timing.log_file"] = args.timing_log
        # note that you can configure tracing without actually enabling it
        # this is to allow message- or exchange-specific tracing (vs global)
        settings["trace.target"] = "log"
        settings["trace.tag"] = ""
        if args.trace:
            settings["trace.enabled"] = True
        if args.trace_target:
            settings["trace.target"] = args.trace_target
        if args.trace_tag:
            settings["trace.tag"] = args.trace_tag
        if args.trace_label:
            settings["trace.label"] = args.trace_label
        elif args.label:
            settings["trace.label"] = args.label
        else:
            settings["trace.label"] = "aca-py.agent"
        if settings.get("trace.enabled") or settings.get("trace.target"):
            # make sure we can trace to the configured target
            # (target can be set even if tracing is off)
            try:
                trace_event(
                    settings,
                    None,
                    handler="ArgParse",
                    outcome="Successfully_configured_aca-py",
                    raise_errors=True,
                    force_trace=True,
                )
            except Exception as e:
                raise ArgsParseError("Error writing trace event " + str(e))
        if args.preserve_exchange_records:
            settings["preserve_exchange_records"] = True
        if args.exch_use_unencrypted_tags:
            settings["exch_use_unencrypted_tags"] = True
            environ["EXCH_UNENCRYPTED_TAGS"] = "True"
        return settings


@group(CAT_START)
class StartupGroup(ArgumentGroup):
    """Startup settings."""

    GROUP_NAME = "Start-up"

    def add_arguments(self, parser: ArgumentParser):
        """Add startup-specific command line arguments to the parser."""
        parser.add_argument(
            "--auto-provision",
            action="store_true",
            env_var="ACAPY_AUTO_PROVISION",
            help="If the requested profile does not exist, initialize it with\
            the given parameters.",
        )

    def get_settings(self, args: Namespace):
        """Extract startup settings."""
        settings = {}
        if args.auto_provision:
            settings["auto_provision"] = True
        return settings


@group(CAT_START)
class TransportGroup(ArgumentGroup):
    """Transport settings."""

    GROUP_NAME = "Transport"

    def add_arguments(self, parser: ArgumentParser):
        """Add transport-specific command line arguments to the parser."""
        parser.add_argument(
            "-it",
            "--inbound-transport",
            dest="inbound_transports",
            type=str,
            action="append",
            nargs=3,
            metavar=("<module>", "<host>", "<port>"),
            env_var="ACAPY_INBOUND_TRANSPORT",
            help="REQUIRED. Defines the inbound transport(s) on which the agent\
            listens for receiving messages from other agents. This parameter can\
            be specified multiple times to create multiple interfaces.\
            Built-in inbound transport types include 'http' and 'ws'.\
            However, other transports can be loaded by specifying an absolute\
            module path.",
        )
        parser.add_argument(
            "-ot",
            "--outbound-transport",
            dest="outbound_transports",
            type=str,
            action="append",
            metavar="<module>",
            env_var="ACAPY_OUTBOUND_TRANSPORT",
            help="REQUIRED. Defines the outbound transport(s) on which the agent\
            will send outgoing messages to other agents. This parameter can be passed\
            multiple times to supoort multiple transport types. Supported outbound\
            transport types are 'http' and 'ws'.",
        )
        parser.add_argument(
            "-oq",
            "--outbound-queue",
            dest="outbound_queue",
            type=str,
            env_var="ACAPY_OUTBOUND_TRANSPORT_QUEUE",
            help="""Defines connection details for outbound queue in a single
                    connection string. For example, 'redis://127.0.0.1:6379'.
                 """,
        )
        parser.add_argument(
            "-oqp",
            "--outbound-queue-prefix",
            dest="outbound_queue_prefix",
            type=str,
            env_var="ACAPY_OUTBOUND_TRANSPORT_QUEUE_PREFIX",
            help="""Defines the prefix used to generate the queue key. The
                    default is 'acapy', which generates a queue key as follows:
                    'acapy.outbound_transport'.
                 """,
        )
        parser.add_argument(
            "-oqc",
            "--outbound-queue-class",
            dest="outbound_queue_class",
            type=str,
            env_var="ACAPY_OUTBOUND_TRANSPORT_QUEUE_CLASS",
            help="""Defines the location of the Outbound Queue Engine. This must be
                    a 'dotpath' to a Python module on the PYTHONPATH, followed by a
                    colon, followed by the name of a Python class that implements
                    BaseOutboundQueue. This commandline option is the official entry
                    point of ACA-py's pluggable queue interface. The default value is:
                    'aries_cloudagent.transport.outbound.queue.redis:RedisOutboundQueue'
                 """,
        )
        parser.add_argument(
            "-l",
            "--label",
            type=str,
            metavar="<label>",
            env_var="ACAPY_LABEL",
            help="Specifies the label for this agent. This label is publicized\
            (self-attested) to other agents as part of forming a connection.",
        )
        parser.add_argument(
            "--image-url",
            type=str,
            env_var="ACAPY_IMAGE_URL",
            help="Specifies the image url for this agent. This image url is publicized\
            (self-attested) to other agents as part of forming a connection.",
        )
        parser.add_argument(
            "--max-message-size",
            default=2097152,
            type=ByteSize(min=1024),
            metavar="<message-size>",
            env_var="ACAPY_MAX_MESSAGE_SIZE",
            help="Set the maximum size in bytes for inbound agent messages.",
        )
        parser.add_argument(
            "--enable-undelivered-queue",
            action="store_true",
            env_var="ACAPY_ENABLE_UNDELIVERED_QUEUE",
            help="Enable the outbound undelivered queue that enables this agent\
            to hold messages for delivery to agents without an endpoint. This\
            option will require additional memory to store messages in the queue.",
        )
        parser.add_argument(
            "--max-outbound-retry",
            default=4,
            type=BoundedInt(min=1),
            env_var="ACAPY_MAX_OUTBOUND_RETRY",
            help="Set the maximum retry number for undelivered outbound\
            messages. Increasing this number might cause to increase the\
            accumulated messages in message queue. Default value is 4.",
        )

    def get_settings(self, args: Namespace):
        """Extract transport settings."""
        settings = {}
        if args.inbound_transports:
            settings["transport.inbound_configs"] = args.inbound_transports
        else:
            raise ArgsParseError("-it/--inbound-transport is required")
        if not args.outbound_transports and not args.outbound_queue:
            raise ArgsParseError(
                "-ot/--outbound-transport or -oq/--outbound-queue is required"
            )
        if args.outbound_transports and args.outbound_queue:
            raise ArgsParseError(
                "-ot/--outbound-transport and -oq/--outbound-queue are "
                "not allowed together"
            )
        if args.outbound_transports:
            settings["transport.outbound_configs"] = args.outbound_transports
        if args.outbound_queue:
            settings["transport.outbound_queue"] = args.outbound_queue
        settings["transport.outbound_queue_prefix"] = (
            args.outbound_queue_prefix or "acapy"
        )
        settings["transport.outbound_queue_class"] = (
            args.outbound_queue_class
            or "aries_cloudagent.transport.outbound.queue.redis:RedisOutboundQueue"
        )

        settings["transport.enable_undelivered_queue"] = args.enable_undelivered_queue

        if args.label:
            settings["default_label"] = args.label
        if args.image_url:
            settings["image_url"] = args.image_url
        if args.max_message_size:
            settings["transport.max_message_size"] = args.max_message_size
        if args.max_outbound_retry:
            settings["transport.max_outbound_retry"] = args.max_outbound_retry

        return settings


@group(CAT_START)
class MediationGroup(ArgumentGroup):
    """Mediation settings."""

    GROUP_NAME = "Mediation"

    def add_arguments(self, parser: ArgumentParser):
        """Add mediation command line arguments to the parser."""
        parser.add_argument(
            "--open-mediation",
            action="store_true",
            help="Enables didcomm mediation. After establishing a connection, if enabled, \
                an agent may request message mediation, which will allow the mediator to \
                forward messages on behalf of the recipient. See aries-rfc:0211.",
        )
        parser.add_argument(
            "--mediator-invitation",
            type=str,
            metavar="<invite URL to mediator>",
            env_var="ACAPY_MEDIATION_INVITATION",
            help="Connect to mediator through provided invitation\
            and send mediation request and set as default mediator.",
        )
        parser.add_argument(
            "--mediator-connections-invite",
            action="store_true",
            env_var="ACAPY_MEDIATION_CONNECTIONS_INVITE",
            help="Connect to mediator through a connection invitation. \
                If not specified, connect using an OOB invitation. \
                Default: false.",
        )
        parser.add_argument(
            "--default-mediator-id",
            type=str,
            metavar="<mediation id>",
            env_var="ACAPY_DEFAULT_MEDIATION_ID",
            help="Set the default mediator by ID",
        )
        parser.add_argument(
            "--clear-default-mediator",
            action="store_true",
            env_var="ACAPY_CLEAR_DEFAULT_MEDIATOR",
            help="Clear the stored default mediator.",
        )

    def get_settings(self, args: Namespace):
        """Extract mediation settings."""
        settings = {}
        if args.open_mediation:
            settings["mediation.open"] = True
        if args.mediator_invitation:
            settings["mediation.invite"] = args.mediator_invitation
        if args.default_mediator_id:
            settings["mediation.default_id"] = args.default_mediator_id
        if args.clear_default_mediator:
            settings["mediation.clear"] = True
        if args.mediator_connections_invite:
            settings["mediation.connections_invite"] = True

        if args.clear_default_mediator and args.default_mediator_id:
            raise ArgsParseError(
                "Cannot both set and clear mediation at the same time."
            )

        return settings


@group(CAT_PROVISION, CAT_START)
class WalletGroup(ArgumentGroup):
    """Wallet settings."""

    GROUP_NAME = "Wallet"

    def add_arguments(self, parser: ArgumentParser):
        """Add wallet-specific command line arguments to the parser."""
        parser.add_argument(
            "--seed",
            type=str,
            metavar="<wallet-seed>",
            env_var="ACAPY_WALLET_SEED",
            help="Specifies the seed to use for the creation of a public\
            DID for the agent to use with a Hyperledger Indy ledger, or a local\
            ('--wallet-local-did') DID. If public, the DID must already exist\
            on the ledger.",
        )
        parser.add_argument(
            "--wallet-local-did",
            action="store_true",
            env_var="ACAPY_WALLET_LOCAL_DID",
            help="If this parameter is set, provisions the wallet with a\
            local DID from the '--seed' parameter, instead of a public DID\
            to use with a Hyperledger Indy ledger.",
        )
        parser.add_argument(
            "--wallet-key",
            type=str,
            metavar="<wallet-key>",
            env_var="ACAPY_WALLET_KEY",
            help="Specifies the master key value to use to open the wallet.",
        )
        parser.add_argument(
            "--wallet-rekey",
            type=str,
            metavar="<wallet-rekey>",
            env_var="ACAPY_WALLET_REKEY",
            help="Specifies a new master key value to which to rotate and to\
            open the wallet next time.",
        )
        parser.add_argument(
            "--wallet-name",
            type=str,
            metavar="<wallet-name>",
            env_var="ACAPY_WALLET_NAME",
            help="Specifies the wallet name to be used by the agent.\
            This is useful if your deployment has multiple wallets.",
        )
        parser.add_argument(
            "--wallet-type",
            type=str,
            metavar="<wallet-type>",
            default="basic",
            env_var="ACAPY_WALLET_TYPE",
            help="Specifies the type of Indy wallet provider to use.\
            Supported internal storage types are 'basic' (memory) and 'indy'.\
            The default (if not specified) is 'basic'.",
        )
        parser.add_argument(
            "--wallet-storage-type",
            type=str,
            metavar="<storage-type>",
            default="default",
            env_var="ACAPY_WALLET_STORAGE_TYPE",
            help="Specifies the type of Indy wallet backend to use.\
            Supported internal storage types are 'basic' (memory),\
            'default' (sqlite), and 'postgres_storage'.  The default,\
            if not specified, is 'default'.",
        )
        parser.add_argument(
            "--wallet-storage-config",
            type=str,
            metavar="<storage-config>",
            env_var="ACAPY_WALLET_STORAGE_CONFIG",
            help='Specifies the storage configuration to use for the wallet.\
            This is required if you are for using \'postgres_storage\' wallet\
            storage type. For example, \'{"url":"localhost:5432",\
            "wallet_scheme":"MultiWalletSingleTable"}\'. This\
            configuration maps to the indy sdk postgres plugin\
            (PostgresConfig).',
        )
        parser.add_argument(
            "--wallet-storage-creds",
            type=str,
            metavar="<storage-creds>",
            env_var="ACAPY_WALLET_STORAGE_CREDS",
            help='Specifies the storage credentials to use for the wallet.\
            This is required if you are for using \'postgres_storage\' wallet\
            For example, \'{"account":"postgres","password":\
            "mysecretpassword","admin_account":"postgres",\
            "admin_password":"mysecretpassword"}\'. This configuration maps\
            to the indy sdk postgres plugin (PostgresCredentials). NOTE:\
            admin_user must have the CREATEDB role or else initialization\
            will fail.',
        )
        parser.add_argument(
            "--replace-public-did",
            action="store_true",
            env_var="ACAPY_REPLACE_PUBLIC_DID",
            help="If this parameter is set and an agent already has a public DID,\
            and the '--seed' parameter specifies a new DID, the agent will use\
            the new DID in place of the existing DID. Default: false.",
        )
        parser.add_argument(
            "--recreate-wallet",
            action="store_true",
            env_var="ACAPY_RECREATE_WALLET",
            help="If an existing wallet exists with the same name, remove and\
            recreate it during provisioning.",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract wallet settings."""
        settings = {}
        if args.seed:
            settings["wallet.seed"] = args.seed
        if args.wallet_local_did:
            settings["wallet.local_did"] = True
        if args.wallet_key:
            settings["wallet.key"] = args.wallet_key
        if args.wallet_rekey:
            settings["wallet.rekey"] = args.wallet_rekey
        if args.wallet_name:
            settings["wallet.name"] = args.wallet_name
        if args.wallet_storage_type:
            settings["wallet.storage_type"] = args.wallet_storage_type
        if args.wallet_type:
            settings["wallet.type"] = args.wallet_type
        if args.wallet_storage_config:
            settings["wallet.storage_config"] = args.wallet_storage_config
        if args.wallet_storage_creds:
            settings["wallet.storage_creds"] = args.wallet_storage_creds
        if args.replace_public_did:
            settings["wallet.replace_public_did"] = True
        if args.recreate_wallet:
            settings["wallet.recreate"] = True
        # check required settings for 'indy' wallets
        if settings["wallet.type"] == "indy":
            # requires name, key
            if not args.wallet_name or not args.wallet_key:
                raise ArgsParseError(
                    "Parameters --wallet-name and --wallet-key must be provided"
                    + " for indy wallets"
                )
            # postgres storage requires additional configuration
            if (
                "wallet.storage_config" in settings
                and settings["wallet.storage_config"] == "postgres_storage"
            ):
                if not args.wallet_storage_config or not args.wallet_storage_creds:
                    raise ArgsParseError(
                        "Parameters --wallet-storage-config and --wallet-storage-creds"
                        + " must be provided for indy postgres wallets"
                    )
        return settings


@group(CAT_START)
class MultitenantGroup(ArgumentGroup):
    """Multitenant settings."""

    GROUP_NAME = "Multitenant"

    def add_arguments(self, parser: ArgumentParser):
        """Add multitenant-specific command line arguments to the parser."""
        parser.add_argument(
            "--multitenant",
            action="store_true",
            env_var="ACAPY_MULTITENANT",
            help="Enable multitenant mode.",
        )
        parser.add_argument(
            "--jwt-secret",
            type=str,
            metavar="<jwt-secret>",
            env_var="ACAPY_MULTITENANT_JWT_SECRET",
            help="Specify the secret to be used for Json Web Token (JWT) \
            creation and verification. The JWTs are used to authenticate and authorize \
            multitenant wallets.",
        )
        parser.add_argument(
            "--multitenant-admin",
            action="store_true",
            env_var="ACAPY_MULTITENANT_ADMIN",
            help="Specify whether to enable the multitenant admin api.",
        )

    def get_settings(self, args: Namespace):
        """Extract multitenant settings."""
        settings = {}
        if args.multitenant:
            settings["multitenant.enabled"] = True

            if args.jwt_secret:
                settings["multitenant.jwt_secret"] = args.jwt_secret
            else:
                raise ArgsParseError(
                    "Parameter --jwt-secret must be provided in multitenant mode"
                )

            if args.multitenant_admin:
                settings["multitenant.admin_enabled"] = True
        return settings
