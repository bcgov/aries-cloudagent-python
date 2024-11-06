"""Command line option parsing."""

import abc
import json
from functools import reduce
from itertools import chain
from os import environ
from typing import Optional, Type

import deepmerge
import yaml
from configargparse import ArgumentParser, Namespace, YAMLConfigFileParser

from ..utils.tracing import trace_event
from .error import ArgsParseError
from .plugin_settings import PLUGIN_CONFIG_KEY
from .util import BoundedInt, ByteSize

CAT_PROVISION = "general"
CAT_START = "start"
CAT_UPGRADE = "upgrade"

ENDORSER_AUTHOR = "author"
ENDORSER_ENDORSER = "endorser"
ENDORSER_NONE = "none"


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
    def get_registered(cls, category: Optional[str] = None):
        """Fetch the set of registered classes in a category."""
        return (
            grp for (cats, grp) in cls._registered if category is None or category in cats
        )


def create_argument_parser(*, prog: Optional[str] = None):
    """Create an instance of an arg parser, force yaml format for external config."""
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
            parser.print_help()
            raise e
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
            help=(
                "Specify the host and port on which to run the administrative server. "
                "If not provided, no admin server is made available."
            ),
        )
        parser.add_argument(
            "--admin-api-key",
            type=str,
            metavar="<api-key>",
            env_var="ACAPY_ADMIN_API_KEY",
            help=(
                "Protect all admin endpoints with the provided API key. "
                "API clients (e.g. the controller) must pass the key in the HTTP "
                "header using 'X-API-Key: <api key>'. Either this parameter or the "
                "'--admin-insecure-mode' parameter MUST be specified."
            ),
        )
        parser.add_argument(
            "--admin-insecure-mode",
            action="store_true",
            env_var="ACAPY_ADMIN_INSECURE_MODE",
            help=(
                "Run the admin web server in insecure mode. DO NOT USE FOR "
                "PRODUCTION DEPLOYMENTS. The admin server will be publicly available "
                "to anyone who has access to the interface. Either this parameter or "
                "the '--api-key' parameter MUST be specified."
            ),
        )
        parser.add_argument(
            "--no-receive-invites",
            action="store_true",
            env_var="ACAPY_NO_RECEIVE_INVITES",
            help=(
                "Prevents an agent from receiving invites by removing the "
                "'/connections/receive-invite' route from the administrative "
                "interface. Default: false."
            ),
        )
        parser.add_argument(
            "--help-link",
            type=str,
            metavar="<help-url>",
            env_var="ACAPY_HELP_LINK",
            help=(
                "A URL to an administrative interface help web page that a controller "
                "user interface can get from the agent and provide as a link to users."
            ),
        )
        parser.add_argument(
            "--webhook-url",
            action="append",
            metavar="<url#api_key>",
            env_var="ACAPY_WEBHOOK_URL",
            help=(
                "Send webhooks containing internal state changes to the specified "
                "URL. Optional API key to be passed in the request body can be "
                "appended using a hash separator [#]. This is useful for a controller "
                "to monitor agent events and respond to those events using the "
                "admin API. If not specified, webhooks are not published by the agent."
            ),
        )
        parser.add_argument(
            "--admin-client-max-request-size",
            default=1,
            type=BoundedInt(min=1, max=16),
            env_var="ACAPY_ADMIN_CLIENT_MAX_REQUEST_SIZE",
            help="Maximum client request size to admin server, in megabytes: default 1",
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
                    "must be set but not both."
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

            settings["admin.admin_client_max_request_size"] = (
                args.admin_client_max_request_size or 1
            )
        return settings


@group(CAT_PROVISION, CAT_START, CAT_UPGRADE)
class DebuggerGroup(ArgumentGroup):
    """Debugger settings."""

    GROUP_NAME = "Debugger"

    def add_arguments(self, parser: ArgumentParser):
        """Add debug command line arguments to the parser."""
        parser.add_argument(
            "--debug",
            action="store_true",
            env_var="ACAPY_DEBUG",
            help=(
                "Enables a remote debugging service that can be accessed "
                "using the Debug Adapter Protocol (supported by Visual Studio Code). "
                "The framework will wait for the debugger to connect at start-up. "
                "Default: false."
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract debug settings."""
        settings = {}
        if args.debug:
            settings["debug.enabled"] = True
        return settings


@group(CAT_START)
class DebugGroup(ArgumentGroup):
    """Debug settings."""

    GROUP_NAME = "Debug"

    def add_arguments(self, parser: ArgumentParser):
        """Add debug command line arguments to the parser."""
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
            help=(
                "Enable additional logging around credential exchanges. Default: false."
            ),
        )
        parser.add_argument(
            "--debug-presentations",
            action="store_true",
            env_var="ACAPY_DEBUG_PRESENTATIONS",
            help=(
                "Enable additional logging around presentation exchanges. Default: false."
            ),
        )
        parser.add_argument(
            "--debug-webhooks",
            action="store_true",
            env_var="ACAPY_DEBUG_WEBHOOKS",
            help=("Emit protocol state object as webhook. Default: false."),
        )
        parser.add_argument(
            "--invite",
            action="store_true",
            env_var="ACAPY_INVITE",
            help=(
                "After startup, generate and print a new out-of-band connection "
                "invitation URL. Default: false."
            ),
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
            help=(
                "Automatically accept invites without firing a webhook event or "
                "waiting for an admin request. Default: false."
            ),
        )
        parser.add_argument(
            "--auto-accept-requests",
            action="store_true",
            env_var="ACAPY_AUTO_ACCEPT_REQUESTS",
            help=(
                "Automatically accept connection requests without firing "
                "a webhook event or waiting for an admin request. Default: false."
            ),
        )
        parser.add_argument(
            "--auto-respond-messages",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_MESSAGES",
            help=(
                "Automatically respond to basic messages indicating the message was "
                "received. Default: false."
            ),
        )
        parser.add_argument(
            "--auto-respond-credential-proposal",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_CREDENTIAL_PROPOSAL",
            help=(
                "Auto-respond to credential proposals with corresponding "
                "credential offers"
            ),
        )
        parser.add_argument(
            "--auto-respond-credential-offer",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_CREDENTIAL_OFFER",
            help=(
                "Automatically respond to Indy credential offers with a credential "
                "request. Default: false"
            ),
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
            help=(
                "Auto-respond to presentation proposals with corresponding "
                "presentation requests"
            ),
        )
        parser.add_argument(
            "--auto-respond-presentation-request",
            action="store_true",
            env_var="ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST",
            help=(
                "Automatically respond to Indy presentation requests with a "
                "constructed presentation if a corresponding credential can be "
                "retrieved for every referent in the presentation request. "
                "Default: false."
            ),
        )
        parser.add_argument(
            "--auto-store-credential",
            action="store_true",
            env_var="ACAPY_AUTO_STORE_CREDENTIAL",
            help=(
                "Automatically store an issued credential upon receipt. Default: false."
            ),
        )
        parser.add_argument(
            "--auto-verify-presentation",
            action="store_true",
            env_var="ACAPY_AUTO_VERIFY_PRESENTATION",
            help=(
                "Automatically verify a presentation when it is received. Default: false."
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract debug settings."""
        settings = {}
        if args.debug_connections:
            settings["debug.connections"] = True
        if args.debug_credentials:
            settings["debug.credentials"] = True
        if args.debug_presentations:
            settings["debug.presentations"] = True
        if args.debug_webhooks:
            settings["debug.webhooks"] = True
        if args.debug_seed:
            settings["debug.seed"] = args.debug_seed
        if args.invite:
            settings["debug.print_invitation"] = True
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


@group(CAT_START)
class DiscoverFeaturesGroup(ArgumentGroup):
    """Discover Features settings."""

    GROUP_NAME = "Discover features"

    def add_arguments(self, parser: ArgumentParser):
        """Add discover features specific command line arguments to the parser."""
        parser.add_argument(
            "--auto-disclose-features",
            action="store_true",
            env_var="ACAPY_AUTO_DISCLOSE_FEATURES",
            help=(
                "Specifies that the agent will proactively/auto disclose protocols"
                " and goal-codes features on connection creation [RFC0557]."
            ),
        )
        parser.add_argument(
            "--disclose-features-list",
            type=str,
            dest="disclose_features_list",
            required=False,
            env_var="ACAPY_DISCLOSE_FEATURES_LIST",
            help="Load YAML file path that specifies which features to disclose.",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract discover features settings."""
        settings = {}
        if args.auto_disclose_features:
            settings["auto_disclose_features"] = True
        if args.disclose_features_list:
            with open(args.disclose_features_list, "r") as stream:
                provided_lists = yaml.safe_load(stream)
                if "protocols" in provided_lists:
                    settings["disclose_protocol_list"] = provided_lists.get("protocols")
                if "goal-codes" in provided_lists:
                    settings["disclose_goal_code_list"] = provided_lists.get("goal-codes")
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
            help=(
                "Load aca-py arguments from the specified file.  Note that "
                "this file *must* be in YAML format."
            ),
        )
        parser.add_argument(
            "--plugin",
            dest="external_plugins",
            type=str,
            action="append",
            required=False,
            metavar="<module>",
            env_var="ACAPY_PLUGIN",
            help=(
                "Load <module> as external plugin module. Multiple "
                "instances of this parameter can be specified."
            ),
        )

        parser.add_argument(
            "--block-plugin",
            dest="blocked_plugins",
            type=str,
            action="append",
            required=False,
            metavar="<module>",
            env_var="ACAPY_BLOCKED_PLUGIN",
            help=(
                "Block <module> plugin module from loading. Multiple "
                "instances of this parameter can be specified."
            ),
        )

        parser.add_argument(
            "--plugin-config",
            dest="plugin_config",
            type=str,
            required=False,
            env_var="ACAPY_PLUGIN_CONFIG",
            help="Load YAML file path that defines external plugin configuration.",
        )

        parser.add_argument(
            "-o",
            "--plugin-config-value",
            dest="plugin_config_values",
            type=str,
            nargs="+",
            action="append",
            required=False,
            metavar="<KEY=VALUE>",
            help=(
                "Set an arbitrary plugin configuration option in the format "
                "KEY=VALUE. Use dots in KEY to set deeply nested values, as in "
                '"a.b.c=value". VALUE is parsed as yaml.'
            ),
        )

        parser.add_argument(
            "--storage-type",
            type=str,
            metavar="<storage-type>",
            env_var="ACAPY_STORAGE_TYPE",
            help=(
                "DEPRECATED: This option is ignored. "
                "Specifies the type of storage provider to use for the internal "
                "storage engine. This storage interface is used to store internal "
                "state. Supported internal storage types are 'basic' (memory) "
                "and 'indy'.  The default (if not specified) is 'indy' if the "
                "wallet type is set to 'indy', otherwise 'basic'."
            ),
        )
        parser.add_argument(
            "-e",
            "--endpoint",
            type=str,
            nargs="+",
            metavar="<endpoint>",
            env_var="ACAPY_ENDPOINT",
            help=(
                "Specifies the endpoints to put into DIDDocs "
                "to inform other agents of where they should send messages destined "
                "for this agent. Each endpoint could be one of the specified inbound "
                "transports for this agent, or the endpoint could be that of "
                "another agent (e.g. 'https://example.com/agent-endpoint') if the "
                "routing of messages to this agent by a mediator is configured. "
                "The first endpoint specified will be used in invitations. "
                "The endpoints are used in the formation of a connection "
                "with another agent."
            ),
        )
        parser.add_argument(
            "--profile-endpoint",
            type=str,
            metavar="<profile_endpoint>",
            env_var="ACAPY_PROFILE_ENDPOINT",
            help="Specifies the profile endpoint for the (public) DID.",
        )
        parser.add_argument(
            "--universal-resolver",
            type=str,
            nargs="?",
            metavar="<universal_resolver_endpoint>",
            env_var="ACAPY_UNIVERSAL_RESOLVER",
            const="DEFAULT",
            help="Enable resolution from a universal resolver.",
        )
        parser.add_argument(
            "--universal-resolver-regex",
            type=str,
            nargs="+",
            metavar="<did_regex>",
            env_var="ACAPY_UNIVERSAL_RESOLVER_REGEX",
            help=(
                "Regex matching DIDs to resolve using the unversal resolver. "
                "Multiple can be specified. "
                "Defaults to a regex matching all DIDs resolvable by universal "
                "resolver instance."
            ),
        )
        (
            parser.add_argument(
                "--universal-resolver-bearer-token",
                type=str,
                nargs="?",
                metavar="<universal_resolver_token>",
                env_var="ACAPY_UNIVERSAL_RESOLVER_BEARER_TOKEN",
                help="Bearer token if universal resolver instance requires authentication.",  # noqa: E501
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract general settings."""
        settings = {}
        if args.external_plugins:
            settings["external_plugins"] = args.external_plugins

        if args.blocked_plugins:
            settings["blocked_plugins"] = args.blocked_plugins

        if args.plugin_config:
            with open(args.plugin_config, "r") as stream:
                settings[PLUGIN_CONFIG_KEY] = yaml.safe_load(stream)

        if args.plugin_config_values:
            if PLUGIN_CONFIG_KEY not in settings:
                settings[PLUGIN_CONFIG_KEY] = {}

            for value_str in chain(*args.plugin_config_values):
                key, value = value_str.split("=", maxsplit=1)
                value = yaml.safe_load(value)
                deepmerge.always_merger.merge(
                    settings[PLUGIN_CONFIG_KEY],
                    reduce(lambda v, k: {k: v}, key.split(".")[::-1], value),
                )

        if args.storage_type:
            settings["storage_type"] = args.storage_type

        if args.endpoint:
            settings["default_endpoint"] = args.endpoint[0]
            settings["additional_endpoints"] = args.endpoint[1:]

        elif "no_transport" not in args:
            raise ArgsParseError("-e/--endpoint is required")

        if args.profile_endpoint:
            settings["profile_endpoint"] = args.profile_endpoint

        if args.universal_resolver_regex and not args.universal_resolver:
            raise ArgsParseError(
                "--universal-resolver-regex cannot be used without --universal-resolver"
            )

        if args.universal_resolver_bearer_token and not args.universal_resolver:
            raise ArgsParseError(
                "--universal-resolver-bearer-token "
                + "cannot be used without --universal-resolver"
            )

        if args.universal_resolver:
            settings["resolver.universal"] = args.universal_resolver

        if args.universal_resolver_regex:
            settings["resolver.universal.supported"] = args.universal_resolver_regex

        if args.universal_resolver_bearer_token:
            settings["resolver.universal.token"] = args.universal_resolver_bearer_token

        return settings


@group(CAT_START, CAT_PROVISION)
class RevocationGroup(ArgumentGroup):
    """Revocation settings."""

    GROUP_NAME = "Revocation"

    def add_arguments(self, parser: ArgumentParser):
        """Add revocation arguments to the parser."""
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
            help=(
                "Sets the base url of the tails server for upload, defaulting to the "
                "tails server base url."
            ),
        )
        parser.add_argument(
            "--notify-revocation",
            action="store_true",
            env_var="ACAPY_NOTIFY_REVOCATION",
            help=(
                "Specifies that aca-py will notify credential recipients when "
                "revoking a credential it issued."
            ),
        )
        parser.add_argument(
            "--monitor-revocation-notification",
            action="store_true",
            env_var="ACAPY_MONITOR_REVOCATION_NOTIFICATION",
            help=(
                "Specifies that aca-py will emit webhooks on notification of "
                "revocation received."
            ),
        )
        parser.add_argument(
            "--anoncreds-legacy-revocation",
            type=str,
            default="accept",
            choices=("accept", "reject"),
            env_var="ACAPY_ANONCREDS_LEGACY_REVOCATION",
            help=(
                "Specify the handling of older proofs of non-revocation "
                "for anoncreds credentials. Values are 'accept' or 'reject'."
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract revocation settings."""
        settings = {}
        if args.tails_server_base_url:
            settings["tails_server_base_url"] = args.tails_server_base_url
            settings["tails_server_upload_url"] = args.tails_server_base_url
        if args.tails_server_upload_url:
            settings["tails_server_upload_url"] = args.tails_server_upload_url
        if args.notify_revocation:
            settings["revocation.notify"] = args.notify_revocation
        if args.monitor_revocation_notification:
            settings["revocation.monitor_notification"] = (
                args.monitor_revocation_notification
            )
        if args.anoncreds_legacy_revocation:
            settings["revocation.anoncreds_legacy_support"] = (
                args.anoncreds_legacy_revocation
            )
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
            help=(
                "Specifies the name of the indy pool to be opened. "
                "This is useful if you have multiple pool configurations."
            ),
        )
        parser.add_argument(
            "--genesis-transactions",
            type=str,
            dest="genesis_transactions",
            metavar="<genesis-transactions>",
            env_var="ACAPY_GENESIS_TRANSACTIONS",
            help=(
                "Specifies the genesis transactions to use to connect to "
                "a Hyperledger Indy ledger. The transactions are provided as string "
                'of JSON e.g. \'{"reqSignature":{},"txn":{"data":{"d... <snip>}}}\''
            ),
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
            help=(
                "Specifies the url from which to download the genesis "
                "transactions. For example, if you are using 'von-network', "
                "the URL might be 'http://localhost:9000/genesis'. "
                "Genesis transactions URLs are available for the "
                "Sovrin test/main networks."
            ),
        )
        parser.add_argument(
            "--no-ledger",
            action="store_true",
            env_var="ACAPY_NO_LEDGER",
            help=(
                "Specifies that aca-py will run with no ledger configured. "
                "This must be set if running in no-ledger mode.  Overrides any "
                "specified ledger or genesis configurations.  Default: false."
            ),
        )
        parser.add_argument(
            "--read-only-ledger",
            action="store_true",
            env_var="ACAPY_READ_ONLY_LEDGER",
            help="Sets ledger to read-only to prevent updates. Default: false.",
        )
        parser.add_argument(
            "--ledger-keepalive",
            default=5,
            type=BoundedInt(min=5),
            env_var="ACAPY_LEDGER_KEEP_ALIVE",
            help="Specifies how many seconds to keep the ledger open. Default: 5",
        )
        parser.add_argument(
            "--ledger-socks-proxy",
            type=str,
            dest="ledger_socks_proxy",
            metavar="<host:port>",
            required=False,
            env_var="ACAPY_LEDGER_SOCKS_PROXY",
            help=(
                "Specifies the socks proxy (NOT http proxy) hostname and port in format "
                "'hostname:port'. This is an optional parameter to be passed to ledger "
                "pool configuration and ZMQ in case if aca-py is running "
                "in a corporate/private network behind a corporate proxy and will "
                "connect to the public (outside of corporate network) ledger pool"
            ),
        )
        parser.add_argument(
            "--genesis-transactions-list",
            type=str,
            required=False,
            dest="genesis_transactions_list",
            metavar="<genesis-transactions-list>",
            env_var="ACAPY_GENESIS_TRANSACTIONS_LIST",
            help=(
                "Load YAML configuration for connecting to multiple"
                " HyperLedger Indy ledgers."
            ),
        )
        parser.add_argument(
            "--accept-taa",
            type=str,
            nargs=2,
            metavar=("<acceptance-mechanism>", "<taa-version>"),
            env_var="ACAPY_ACCEPT_TAA",
            help=(
                "Specify the acceptance mechanism and taa version for which to accept"
                " the transaction author agreement. If not provided, the TAA must"
                " be accepted through the TTY or the admin API."
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract ledger settings."""
        settings = {}
        if args.no_ledger:
            settings["ledger.disabled"] = True
        else:
            single_configured = False
            multi_configured = False
            update_pool_name = False
            write_ledger_specified = False

            if args.read_only_ledger:
                settings["read_only_ledger"] = True
            if args.genesis_url:
                settings["ledger.genesis_url"] = args.genesis_url
                single_configured = True
            elif args.genesis_file:
                settings["ledger.genesis_file"] = args.genesis_file
                single_configured = True
            elif args.genesis_transactions:
                settings["ledger.genesis_transactions"] = args.genesis_transactions
                single_configured = True
            if args.genesis_transactions_list:
                with open(args.genesis_transactions_list, "r") as stream:
                    txn_config_list = yaml.safe_load(stream)
                    ledger_config_list = []
                    for txn_config in txn_config_list:
                        if "is_write" in txn_config and txn_config["is_write"]:
                            write_ledger_specified = True
                        if (
                            "genesis_url" not in txn_config
                            and "genesis_file" not in txn_config
                            and "genesis_transactions" not in txn_config
                        ):
                            raise ArgsParseError(
                                "No genesis information provided for write ledger"
                            )
                        if "id" in txn_config and "pool_name" not in txn_config:
                            txn_config["pool_name"] = txn_config["id"]
                        update_pool_name = True
                        ledger_config_list.append(txn_config)
                    if not write_ledger_specified and not args.read_only_ledger:
                        raise ArgsParseError(
                            "No write ledger genesis provided in multi-ledger config"
                        )
                    settings["ledger.ledger_config_list"] = ledger_config_list
                    multi_configured = True
            if not (single_configured or multi_configured):
                raise ArgsParseError(
                    "One of --genesis-url --genesis-file, --genesis-transactions "
                    "or --genesis-transactions-list must be specified (unless "
                    "--no-ledger is specified to explicitly configure aca-py to"
                    " run with no ledger)."
                )
            if single_configured and multi_configured:
                raise ArgsParseError("Cannot configure both single- and multi-ledger.")
            if args.ledger_pool_name and not update_pool_name:
                settings["ledger.pool_name"] = args.ledger_pool_name
            if args.ledger_keepalive:
                settings["ledger.keepalive"] = args.ledger_keepalive
            if args.ledger_socks_proxy:
                settings["ledger.socks_proxy"] = args.ledger_socks_proxy
            if args.accept_taa:
                settings["ledger.taa_acceptance_mechanism"] = args.accept_taa[0]
                settings["ledger.taa_acceptance_version"] = args.accept_taa[1]

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
            metavar="<log-file>",
            nargs="?",
            const="",
            default=None,
            env_var="ACAPY_LOG_FILE",
            help=(
                "--log-file enables writing of logs to file, if a value is "
                "provided then it uses that as log file location, otherwise "
                "the default location in log config file is used."
            ),
        )
        parser.add_argument(
            "--log-level",
            dest="log_level",
            type=str,
            metavar="<log-level>",
            default=None,
            env_var="ACAPY_LOG_LEVEL",
            help=(
                "Specifies a custom logging level as one of: "
                "('debug', 'info', 'warning', 'error', 'critical')"
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract logging settings."""
        settings = {}
        if args.log_config:
            settings["log.config"] = args.log_config
        if args.log_file or args.log_file == "":
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
            "--auto-ping-connection",
            action="store_true",
            env_var="ACAPY_AUTO_PING_CONNECTION",
            help=(
                "Automatically send a trust ping immediately after a "
                "connection response is accepted. Some agents require this before "
                "marking a connection as 'active'. Default: false."
            ),
        )
        parser.add_argument(
            "--auto-accept-intro-invitation-requests",
            action="store_true",
            env_var="ACAPY_AUTO_ACCEPT_INTRO_INVITATION_REQUESTS",
            help="Automatically accept introduction invitations. Default: false.",
        )
        parser.add_argument(
            "--invite-base-url",
            type=str,
            metavar="<base-url>",
            env_var="ACAPY_INVITE_BASE_URL",
            help=(
                "Base URL to use when formatting connection invitations in URL format."
            ),
        )
        parser.add_argument(
            "--monitor-ping",
            action="store_true",
            env_var="ACAPY_MONITOR_PING",
            help="Send a webhook when a ping is sent or received.",
        )
        parser.add_argument(
            "--monitor-forward",
            action="store_true",
            env_var="ACAPY_MONITOR_FORWARD",
            help="Send a webhook when a forward is received.",
        )
        parser.add_argument(
            "--public-invites",
            action="store_true",
            env_var="ACAPY_PUBLIC_INVITES",
            help=(
                "Send invitations out using the public DID for the agent, "
                "and receive connection requests solicited by invitations "
                "which use the public DID. Default: false."
            ),
        )
        parser.add_argument(
            "--requests-through-public-did",
            action="store_true",
            env_var="ACAPY_REQUESTS_THROUGH_PUBLIC_DID",
            help=(
                "Allow agent to receive unsolicited connection requests, "
                "using the public DID for the agent. Default: false."
            ),
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
            help="Keep credential and presentation exchange records after "
            "exchange has completed.",
        )
        parser.add_argument(
            "--emit-new-didcomm-prefix",
            action="store_true",
            env_var="ACAPY_EMIT_NEW_DIDCOMM_PREFIX",
            help=(
                "Emit protocol messages with new DIDComm prefix; i.e., "
                "'https://didcomm.org/' instead of (default) prefix "
                "'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/'. "
                "Forced to `true` as the old prefix must never be used."
            ),
        )
        parser.add_argument(
            "--emit-new-didcomm-mime-type",
            action="store_true",
            env_var="ACAPY_EMIT_NEW_DIDCOMM_MIME_TYPE",
            help=(
                "Send packed agent messages with the DIDComm MIME type "
                "as of RFC 0044; i.e., 'application/didcomm-envelope-enc' "
                "instead of 'application/ssi-agent-wire'. "
                "Forced to `true` as the old MIME type must never be used."
            ),
        )
        parser.add_argument(
            "--exch-use-unencrypted-tags",
            action="store_true",
            env_var="ACAPY_EXCH_USE_UNENCRYPTED_TAGS",
            help=(
                "Store tags for exchange protocols (credential and presentation) "
                "using unencrypted rather than encrypted tags"
            ),
        )

        parser.add_argument(
            "--experimental-didcomm-v2",
            action="store_true",
            env_var="ACAPY_EXP_DIDCOMM_V2",
            help="Enable experimental DIDComm V2 support.",
        )

    def get_settings(self, args: Namespace) -> dict:
        """Get protocol settings."""
        settings = {}
        if args.auto_ping_connection:
            settings["auto_ping_connection"] = True
        if args.auto_accept_intro_invitation_requests:
            settings["auto_accept_intro_invitation_requests"] = True
        if args.invite_base_url:
            settings["invite_base_url"] = args.invite_base_url
        if args.monitor_ping:
            settings["debug.monitor_ping"] = args.monitor_ping
        if args.monitor_forward:
            settings["monitor_forward"] = args.monitor_forward
        if args.public_invites:
            settings["public_invites"] = True
        if args.requests_through_public_did:
            if not args.public_invites:
                raise ArgsParseError(
                    "--public-invites is required to use ",
                    "--requests-through-public-did",
                )
            settings["requests_through_public_did"] = True
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
        # NOT setting the following two parameters `True` is no longer supported
        # Even if the args are not set, the config setting is True.
        settings["emit_new_didcomm_prefix"] = True
        settings["emit_new_didcomm_mime_type"] = True
        if args.exch_use_unencrypted_tags:
            settings["exch_use_unencrypted_tags"] = True
            environ["EXCH_UNENCRYPTED_TAGS"] = "True"
        if args.experimental_didcomm_v2:
            settings["experiment.didcomm_v2"] = True

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
            help=(
                "If the requested profile does not exist, initialize it with "
                "the given parameters."
            ),
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
            "--no-transport",
            dest="no_transport",
            action="store_true",
            env_var="ACAPY_NO_TRANSPORT",
            help=(
                "Specifies that aca-py will run with no transport configured. "
                "This must be set if running in no-transport mode.  Overrides any "
                "specified transport or endpoint configurations.  "
                "Either this parameter or the "
                "'--endpoint' parameter MUST be specified. Default: false."
            ),
        )
        parser.add_argument(
            "-it",
            "--inbound-transport",
            dest="inbound_transports",
            type=str,
            action="append",
            nargs=3,
            metavar=("<module>", "<host>", "<port>"),
            env_var="ACAPY_INBOUND_TRANSPORT",
            help=(
                "REQUIRED. Defines the inbound transport(s) on which the agent "
                "listens for receiving messages from other agents. This parameter can "
                "be specified multiple times to create multiple interfaces. "
                "Built-in inbound transport types include 'http' and 'ws'. "
                "However, other transports can be loaded by specifying an absolute "
                "module path."
            ),
        )
        parser.add_argument(
            "-ot",
            "--outbound-transport",
            dest="outbound_transports",
            type=str,
            action="append",
            metavar="<module>",
            env_var="ACAPY_OUTBOUND_TRANSPORT",
            help=(
                "REQUIRED. Defines the outbound transport(s) on which the agent "
                "will send outgoing messages to other agents. This parameter can be "
                "passed multiple times to supoort multiple transport types. "
                "Supported outbound transport types are 'http' and 'ws'."
            ),
        )
        parser.add_argument(
            "-l",
            "--label",
            type=str,
            metavar="<label>",
            env_var="ACAPY_LABEL",
            help=(
                "Specifies the label for this agent. This label is publicized "
                "(self-attested) to other agents as part of forming a connection."
            ),
        )
        parser.add_argument(
            "--image-url",
            type=str,
            env_var="ACAPY_IMAGE_URL",
            help=(
                "Specifies the image url for this agent. This image url is publicized "
                "(self-attested) to other agents as part of forming a connection."
            ),
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
            help=(
                "Enable the outbound undelivered queue that enables this agent "
                "to hold messages for delivery to agents without an endpoint. This "
                "option will require additional memory to store messages in the queue."
            ),
        )
        parser.add_argument(
            "--max-outbound-retry",
            default=4,
            type=BoundedInt(min=1),
            env_var="ACAPY_MAX_OUTBOUND_RETRY",
            help=(
                "Set the maximum retry number for undelivered outbound "
                "messages. Increasing this number might cause to increase the "
                "accumulated messages in message queue. Default value is 4."
            ),
        )
        parser.add_argument(
            "--ws-heartbeat-interval",
            default=3,
            type=BoundedInt(min=1),
            env_var="ACAPY_WS_HEARTBEAT_INTERVAL",
            metavar="<interval>",
            help=(
                "When using Websocket Inbound Transport, send WS pings every "
                "<interval> seconds."
            ),
        )
        parser.add_argument(
            "--ws-timeout-interval",
            default=15,
            type=BoundedInt(min=1),
            env_var="ACAPY_WS_TIMEOUT_INTERVAL",
            metavar="<interval>",
            help=(
                "When using Websocket Inbound Transport, timeout the WS connection "
                "after <interval> seconds without a heartbeat ping."
            ),
        )

    def get_settings(self, args: Namespace):
        """Extract transport settings."""
        settings = {}
        if args.no_transport:
            settings["transport.disabled"] = True
        else:
            if args.inbound_transports:
                settings["transport.inbound_configs"] = args.inbound_transports
            else:
                raise ArgsParseError("-it/--inbound-transport is required")
            if args.outbound_transports:
                settings["transport.outbound_configs"] = args.outbound_transports
            else:
                raise ArgsParseError("-ot/--outbound-transport is required")
            settings["transport.enable_undelivered_queue"] = args.enable_undelivered_queue
            if args.max_message_size:
                settings["transport.max_message_size"] = args.max_message_size
            if args.max_outbound_retry:
                settings["transport.max_outbound_retry"] = args.max_outbound_retry
            if args.ws_heartbeat_interval:
                settings["transport.ws.heartbeat_interval"] = args.ws_heartbeat_interval
            if args.ws_timeout_interval:
                settings["transport.ws.timeout_interval"] = args.ws_timeout_interval

        if args.label:
            settings["default_label"] = args.label
        if args.image_url:
            settings["image_url"] = args.image_url

        return settings


@group(CAT_START, CAT_PROVISION)
class MediationInviteGroup(ArgumentGroup):
    """Mediation invitation settings.

    These can be provided at provision- and start-time.
    """

    GROUP_NAME = "Mediation invitation"

    def add_arguments(self, parser: ArgumentParser):
        """Add mediation invitation command line arguments to the parser."""
        parser.add_argument(
            "--mediator-invitation",
            type=str,
            metavar="<invite URL to mediator>",
            env_var="ACAPY_MEDIATION_INVITATION",
            help=(
                "Connect to mediator through provided invitation "
                "and send mediation request and set as default mediator."
            ),
        )

    def get_settings(self, args: Namespace):
        """Extract mediation invitation settings."""
        settings = {}
        if args.mediator_invitation:
            settings["mediation.invite"] = args.mediator_invitation

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
            env_var="ACAPY_MEDIATION_OPEN",
            help=(
                "Enables automatic granting of mediation. After establishing a "
                "connection, if enabled, an agent may request message mediation "
                "and be granted it automatically, which will allow the mediator "
                "to forward messages on behalf of the recipient. See "
                "aries-rfc:0211."
            ),
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
        if args.default_mediator_id:
            settings["mediation.default_id"] = args.default_mediator_id
        if args.clear_default_mediator:
            settings["mediation.clear"] = True

        if args.clear_default_mediator and args.default_mediator_id:
            raise ArgsParseError("Cannot both set and clear mediation at the same time.")

        return settings


@group(CAT_PROVISION, CAT_START, CAT_UPGRADE)
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
            help=(
                "Specifies the seed to use for the creation of a public "
                "DID for the agent to use with a Hyperledger Indy ledger, or a local "
                "('--wallet-local-did') DID. If public, the DID must already exist "
                "on the ledger."
            ),
        )
        parser.add_argument(
            "--wallet-local-did",
            action="store_true",
            env_var="ACAPY_WALLET_LOCAL_DID",
            help=(
                "If this parameter is set, provisions the wallet with a "
                "local DID from the '--seed' parameter, instead of a public DID "
                "to use with a Hyperledger Indy ledger."
            ),
        )
        parser.add_argument(
            "--wallet-allow-insecure-seed",
            action="store_true",
            env_var="ACAPY_WALLET_ALLOW_INSECURE_SEED",
            help=(
                "If this parameter is set, allows to use a custom seed "
                "to create a local DID"
            ),
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
            help=(
                "Specifies a new master key value to which to rotate and to "
                "open the wallet next time."
            ),
        )
        parser.add_argument(
            "--wallet-name",
            type=str,
            metavar="<wallet-name>",
            env_var="ACAPY_WALLET_NAME",
            help=(
                "Specifies the wallet name to be used by the agent. "
                "This is useful if your deployment has multiple wallets."
            ),
        )
        parser.add_argument(
            "--wallet-type",
            type=str,
            metavar="<wallet-type>",
            default="askar",
            env_var="ACAPY_WALLET_TYPE",
            help=(
                "Specifies the type of wallet provider to use. "
                "Supported internal storage types are 'askar' "
                "and 'askar-anoncreds'."
                "The default (if not specified) is 'askar'."
            ),
        )
        parser.add_argument(
            "--wallet-storage-type",
            type=str,
            metavar="<storage-type>",
            default="default",
            env_var="ACAPY_WALLET_STORAGE_TYPE",
            help=(
                "Specifies the type of wallet backend to use. "
                "Supported internal storage types are 'default' (sqlite), "
                "and 'postgres_storage'.  The default, "
                "if not specified, is 'default'."
            ),
        )
        parser.add_argument(
            "--wallet-test",
            action="store_true",
            default=False,
            env_var="ACAPY_WALLET_TEST",
            help=(
                "Using this option will create a wallet with an in-memory askar wallet "
                "storage with a random name. This is useful for testing purposes. "
                "The data will not be persisted after the agent is stopped. The default "
                "is False. "
            ),
        )
        parser.add_argument(
            "--wallet-storage-config",
            type=str,
            metavar="<storage-config>",
            env_var="ACAPY_WALLET_STORAGE_CONFIG",
            help=(
                "Specifies the storage configuration to use for the wallet. "
                "This is required if you are for using 'postgres_storage' wallet "
                'storage type. For example, \'{"url":"localhost:5432"}\'.'
            ),
        )
        parser.add_argument(
            "--wallet-key-derivation-method",
            type=str,
            metavar="<key-derivation-method>",
            env_var="ACAPY_WALLET_KEY_DERIVATION_METHOD",
            help=("Specifies the key derivation method used for wallet encryption."),
        )
        parser.add_argument(
            "--wallet-rekey-derivation-method",
            type=str,
            metavar="<rekey-derivation-method>",
            env_var="ACAPY_WALLET_REKEY_DERIVATION_METHOD",
            help=(
                "Specifies the key derivation method used for the replacement"
                "rekey encryption."
            ),
        )
        parser.add_argument(
            "--wallet-storage-creds",
            type=str,
            metavar="<storage-creds>",
            env_var="ACAPY_WALLET_STORAGE_CREDS",
            help=(
                "Specifies the storage credentials to use for the wallet. "
                "This is required if you are for using 'postgres_storage' wallet "
                'For example, \'{"account":"postgres","password": '
                '"mysecretpassword","admin_account":"postgres", '
                '"admin_password":"mysecretpassword"}\'.'
                "NOTE: admin_user must have the CREATEDB role or else initialization "
                "will fail."
            ),
        )
        parser.add_argument(
            "--replace-public-did",
            action="store_true",
            env_var="ACAPY_REPLACE_PUBLIC_DID",
            help=(
                "If this parameter is set and an agent already has a public DID, "
                "and the '--seed' parameter specifies a new DID, the agent will use "
                "the new DID in place of the existing DID. Default: false."
            ),
        )
        parser.add_argument(
            "--recreate-wallet",
            action="store_true",
            env_var="ACAPY_RECREATE_WALLET",
            help=(
                "If an existing wallet exists with the same name, remove and "
                "recreate it during provisioning."
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract wallet settings."""
        settings = {}
        if args.seed:
            settings["wallet.seed"] = args.seed
        if args.wallet_local_did:
            settings["wallet.local_did"] = True
        if args.wallet_allow_insecure_seed:
            settings["wallet.allow_insecure_seed"] = True
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
        if args.wallet_test:
            settings["wallet.test"] = True
        if args.wallet_key_derivation_method:
            settings["wallet.key_derivation_method"] = args.wallet_key_derivation_method
        if args.wallet_rekey_derivation_method:
            settings["wallet.rekey_derivation_method"] = (
                args.wallet_rekey_derivation_method
            )
        if args.wallet_storage_config:
            settings["wallet.storage_config"] = args.wallet_storage_config
        if args.wallet_storage_creds:
            settings["wallet.storage_creds"] = args.wallet_storage_creds
        if args.replace_public_did:
            settings["wallet.replace_public_did"] = True
        if args.recreate_wallet:
            settings["wallet.recreate"] = True
        # check required settings for persistent wallets
        if settings["wallet.type"] in ["askar", "askar-anoncreds"]:
            # requires name, key
            if not args.wallet_test and (not args.wallet_name or not args.wallet_key):
                raise ArgsParseError(
                    "Parameters --wallet-name and --wallet-key must be provided "
                    "for persistent wallets"
                )
            # postgres storage requires additional configuration
            if (
                "wallet.storage_config" in settings
                and settings["wallet.storage_config"] == "postgres_storage"
            ):
                if not args.wallet_storage_config or not args.wallet_storage_creds:
                    raise ArgsParseError(
                        "Parameters --wallet-storage-config and --wallet-storage-creds "
                        "must be provided for postgres wallets"
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
            help=(
                "Specify the secret to be used for Json Web Token (JWT) creation and "
                "verification. The JWTs are used to authenticate and authorize "
                "multitenant wallets."
            ),
        )
        parser.add_argument(
            "--multitenant-admin",
            action="store_true",
            env_var="ACAPY_MULTITENANT_ADMIN",
            help="Specify whether to enable the multitenant admin api.",
        )
        parser.add_argument(
            "--multitenancy-config",
            type=str,
            nargs="+",
            metavar="key=value",
            env_var="ACAPY_MULTITENANCY_CONFIGURATION",
            help=(
                "Specify multitenancy configuration in key=value pairs. "
                'For example: "wallet_type=single-wallet-askar wallet_name=wallet-name" '
                "Possible values: wallet_name, wallet_key, cache_size, "
                'key_derivation_method. "wallet_name" is only used when '
                '"wallet_type" is "single-wallet-askar"'
            ),
        )
        parser.add_argument(
            "--base-wallet-routes",
            type=str,
            nargs="+",
            required=False,
            metavar="<REGEX>",
            help=(
                "Patterns matching admin routes that should be permitted for "
                "base wallet. The base wallet is preconfigured to have access to "
                "essential endpoints. This argument should be used sparingly."
            ),
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

            if args.multitenancy_config:
                # Legacy support
                if (
                    len(args.multitenancy_config) == 1
                    and args.multitenancy_config[0][0] == "{"
                ):
                    multitenancy_config = json.loads(args.multitenancy_config[0])
                    if multitenancy_config.get("wallet_type"):
                        settings["multitenant.wallet_type"] = multitenancy_config.get(
                            "wallet_type"
                        )

                    if multitenancy_config.get("wallet_name"):
                        settings["multitenant.wallet_name"] = multitenancy_config.get(
                            "wallet_name"
                        )

                    if multitenancy_config.get("cache_size"):
                        settings["multitenant.cache_size"] = multitenancy_config.get(
                            "cache_size"
                        )

                    if multitenancy_config.get("key_derivation_method"):
                        settings["multitenant.key_derivation_method"] = (
                            multitenancy_config.get("key_derivation_method")
                        )

                else:
                    for value_str in args.multitenancy_config:
                        key, value = value_str.split("=", maxsplit=1)
                        value = yaml.safe_load(value)
                        settings[f"multitenant.{key}"] = value

            if args.base_wallet_routes:
                settings["multitenant.base_wallet_routes"] = args.base_wallet_routes

        return settings


@group(CAT_START)
class EndorsementGroup(ArgumentGroup):
    """Endorsement settings."""

    GROUP_NAME = "Endorsement"

    def add_arguments(self, parser: ArgumentParser):
        """Add endorsement-specific command line arguments to the parser."""
        parser.add_argument(
            "--endorser-protocol-role",
            type=str.lower,
            choices=[ENDORSER_AUTHOR, ENDORSER_ENDORSER, ENDORSER_NONE],
            metavar="<endorser-role>",
            env_var="ACAPY_ENDORSER_ROLE",
            help=(
                "Specify the role ('author' or 'endorser') which this agent will "
                "participate. Authors will request transaction endorement from an "
                "Endorser. Endorsers will endorse transactions from Authors, and "
                "may write their own transactions to the ledger. If no role "
                "(or 'none') is specified then the endorsement protocol will not "
                "be used and this agent will write transactions to the ledger "
                "directly."
            ),
        )
        parser.add_argument(
            "--endorser-invitation",
            type=str,
            metavar="<endorser-invitation>",
            env_var="ACAPY_ENDORSER_INVITATION",
            help=(
                "For transaction Authors, specify the invitation used to "
                "connect to the Endorser agent who will be endorsing transactions. "
                "Note this is a multi-use invitation created by the Endorser agent."
            ),
        )
        parser.add_argument(
            "--endorser-public-did",
            type=str,
            metavar="<endorser-public-did>",
            env_var="ACAPY_ENDORSER_PUBLIC_DID",
            help=(
                "For transaction Authors, specify the public DID of the Endorser "
                "agent who will be endorsing transactions."
            ),
        )
        parser.add_argument(
            "--endorser-endorse-with-did",
            type=str,
            metavar="<endorser-endorse-with-did>",
            env_var="ACAPY_ENDORSER_ENDORSE_WITH_DID",
            help=(
                "For transaction Endorsers, specify the DID to use to endorse "
                "transactions.  The default (if not specified) is to use the "
                "Endorser's Public DID."
            ),
        )
        parser.add_argument(
            "--endorser-alias",
            type=str,
            metavar="<endorser-alias>",
            env_var="ACAPY_ENDORSER_ALIAS",
            help=(
                "For transaction Authors, specify the alias of the Endorser "
                "connection that will be used to endorse transactions."
            ),
        )
        parser.add_argument(
            "--auto-request-endorsement",
            action="store_true",
            env_var="ACAPY_AUTO_REQUEST_ENDORSEMENT",
            help="For Authors, specify whether to automatically request "
            "endorsement for all transactions. (If not specified, the controller "
            " must invoke the request endorse operation for each transaction.)",
        )
        parser.add_argument(
            "--auto-endorse-transactions",
            action="store_true",
            env_var="ACAPY_AUTO_ENDORSE_TRANSACTIONS",
            help="For Endorsers, specify whether to automatically endorse any "
            "received endorsement requests. (If not specified, the controller "
            " must invoke the endorsement operation for each transaction.)",
        )
        parser.add_argument(
            "--auto-write-transactions",
            action="store_true",
            env_var="ACAPY_AUTO_WRITE_TRANSACTIONS",
            help="For Authors, specify whether to automatically write any "
            "endorsed transactions. (If not specified, the controller "
            " must invoke the write transaction operation for each transaction.)",
        )
        parser.add_argument(
            "--auto-create-revocation-transactions",
            action="store_true",
            env_var="ACAPY_CREATE_REVOCATION_TRANSACTIONS",
            help="For Authors, specify whether to automatically create"
            " transactions for a cred def's revocation registry. (If not specified,"
            " the controller must invoke the endpoints required to create the"
            " revocation registry and assign to the cred def.)",
        )
        parser.add_argument(
            "--auto-promote-author-did",
            action="store_true",
            env_var="ACAPY_AUTO_PROMOTE_AUTHOR_DID",
            help="For Authors, specify whether to automatically promote"
            " a DID to the wallet public DID after writing to the ledger.",
        )

    def get_settings(self, args: Namespace):
        """Extract endorser settings."""
        settings = {}
        settings["endorser.author"] = False
        settings["endorser.endorser"] = False
        settings["endorser.auto_endorse"] = False
        settings["endorser.auto_write"] = False
        settings["endorser.auto_create_rev_reg"] = False
        settings["endorser.auto_promote_author_did"] = False

        if args.endorser_protocol_role:
            if args.endorser_protocol_role == ENDORSER_AUTHOR:
                settings["endorser.author"] = True
            elif args.endorser_protocol_role == ENDORSER_ENDORSER:
                settings["endorser.endorser"] = True

        if args.endorser_public_did:
            if settings["endorser.author"]:
                settings["endorser.endorser_public_did"] = args.endorser_public_did
            else:
                raise ArgsParseError(
                    "Parameter --endorser-public-did should only be set for transaction "
                    "Authors"
                )

        if args.endorser_endorse_with_did:
            if settings["endorser.endorser"]:
                settings["endorser.endorser_endorse_with_did"] = (
                    args.endorser_endorse_with_did
                )
            else:
                raise ArgsParseError(
                    "Parameter --endorser-endorse-with-did should only be set for "
                    "transaction Endorsers"
                )

        if args.endorser_alias:
            if settings["endorser.author"]:
                settings["endorser.endorser_alias"] = args.endorser_alias
            else:
                raise ArgsParseError(
                    "Parameter --endorser-alias should only be set for transaction "
                    "Authors"
                )

        if args.endorser_invitation:
            if settings["endorser.author"]:
                if not settings.get("endorser.endorser_public_did"):
                    raise ArgsParseError(
                        "Parameter --endorser-public-did must be provided if "
                        "--endorser-invitation is set."
                    )
                if not settings.get("endorser.endorser_alias"):
                    raise ArgsParseError(
                        "Parameter --endorser-alias must be provided if "
                        "--endorser-invitation is set."
                    )
                settings["endorser.endorser_invitation"] = args.endorser_invitation
            else:
                raise ArgsParseError(
                    "Parameter --endorser-invitation should only be set for transaction "
                    "Authors"
                )

        if args.auto_request_endorsement:
            if settings["endorser.author"]:
                settings["endorser.auto_request"] = True
            else:
                raise ArgsParseError(
                    "Parameter --auto-request-endorsement should only be set for "
                    "transaction Authors"
                )

        if args.auto_endorse_transactions:
            if settings["endorser.endorser"]:
                settings["endorser.auto_endorse"] = True
            else:
                raise ArgsParseError(
                    "Parameter --auto-endorser-transactions should only be set for "
                    "transaction Endorsers"
                )

        if args.auto_write_transactions:
            if settings["endorser.author"]:
                settings["endorser.auto_write"] = True
            else:
                raise ArgsParseError(
                    "Parameter --auto-write-transactions should only be set for "
                    "transaction Authors"
                )

        if args.auto_create_revocation_transactions:
            if settings["endorser.author"]:
                settings["endorser.auto_create_rev_reg"] = True
            else:
                raise ArgsParseError(
                    "Parameter --auto-create-revocation-transactions should only be set "
                    "for transaction Authors"
                )

        if args.auto_promote_author_did:
            if settings["endorser.author"]:
                settings["endorser.auto_promote_author_did"] = True
            else:
                raise ArgsParseError(
                    "Parameter --auto-promote-author-did should only be set "
                    "for transaction Authors"
                )

        return settings


@group(CAT_START, CAT_UPGRADE)
class UpgradeGroup(ArgumentGroup):
    """ACA-Py Upgrade process settings."""

    GROUP_NAME = "Upgrade"

    def add_arguments(self, parser: ArgumentParser):
        """Add ACA-Py upgrade process specific arguments to the parser."""

        parser.add_argument(
            "--upgrade-config-path",
            type=str,
            dest="upgrade_config_path",
            required=False,
            env_var="ACAPY_UPGRADE_CONFIG_PATH",
            help=(
                "YAML file path that specifies config to handle upgrade changes."
                "Default: ./acapy_agent/commands/default_version_upgrade_config.yml"
            ),
        )

        parser.add_argument(
            "--from-version",
            type=str,
            env_var="ACAPY_UPGRADE_FROM_VERSION",
            help=(
                "Specify which ACA-Py version to upgrade from, "
                "this version should be supported/included in "
                "the --upgrade-config file."
            ),
        )

        parser.add_argument(
            "--force-upgrade",
            action="store_true",
            env_var="ACAPY_UPGRADE_FORCE_UPGRADE",
            help=(
                "Forces the '—from-version' argument to override the version "
                "retrieved from secure storage when calculating upgrades to "
                "be run."
            ),
        )

        parser.add_argument(
            "--named-tag",
            action="append",
            env_var="ACAPY_UPGRADE_NAMED_TAGS",
            help=("Runs upgrade steps associated with tags provided in the config"),
        )

        parser.add_argument(
            "--upgrade-all-subwallets",
            action="store_true",
            env_var="ACAPY_UPGRADE_ALL_SUBWALLETS",
            help="Apply upgrade to all subwallets and the base wallet",
        )

        parser.add_argument(
            "--upgrade-subwallet",
            action="append",
            env_var="ACAPY_UPGRADE_SUBWALLETS",
            help=(
                "Apply upgrade to specified subwallets (identified by wallet id)"
                " and the base wallet"
            ),
        )

        parser.add_argument(
            "--upgrade-page-size",
            type=str,
            env_var="ACAPY_UPGRADE_PAGE_SIZE",
            help=(
                "Specify page/batch size to process BaseRecords, "
                "this provides a way to prevent out-of-memory issues."
            ),
        )

    def get_settings(self, args: Namespace) -> dict:
        """Extract ACA-Py upgrade process settings."""
        settings = {}
        if args.upgrade_config_path:
            settings["upgrade.config_path"] = args.upgrade_config_path
        if args.from_version:
            settings["upgrade.from_version"] = args.from_version
        if args.force_upgrade:
            settings["upgrade.force_upgrade"] = args.force_upgrade
        if args.named_tag:
            settings["upgrade.named_tags"] = (
                list(args.named_tag) if args.named_tag else []
            )
        if args.upgrade_all_subwallets:
            settings["upgrade.upgrade_all_subwallets"] = args.upgrade_all_subwallets
        if args.upgrade_subwallet:
            settings["upgrade.upgrade_subwallets"] = (
                list(args.upgrade_subwallet) if args.upgrade_subwallet else []
            )
        if args.upgrade_page_size:
            try:
                settings["upgrade.page_size"] = int(args.upgrade_page_size)
            except ValueError:
                raise ArgsParseError("Parameter --upgrade-page-size must be an integer")
        return settings
