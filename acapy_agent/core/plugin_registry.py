"""Handle registration of plugin modules for extending functionality."""

import logging
from collections import OrderedDict
from types import ModuleType
from typing import Optional, Sequence, Set

from ..config.injection_context import InjectionContext
from ..core.event_bus import EventBus
from ..utils.classloader import ClassLoader, ModuleLoadError
from .error import ProtocolDefinitionValidationError
from .goal_code_registry import GoalCodeRegistry
from .protocol_registry import ProtocolRegistry

LOGGER = logging.getLogger(__name__)


class PluginRegistry:
    """Plugin registry for indexing application plugins."""

    def __init__(self, blocklist: Optional[Set[str]] = None):
        """Initialize a `PluginRegistry` instance."""
        self._plugins: OrderedDict[str, ModuleType] = OrderedDict()
        self._blocklist: Set[str] = set(blocklist) if blocklist else set()

    @property
    def plugin_names(self) -> Sequence[str]:
        """Accessor for a list of all plugin modules."""
        return list(self._plugins.keys())

    @property
    def plugins(self) -> Sequence[ModuleType]:
        """Accessor for a list of all plugin modules."""
        return list(self._plugins.values())

    def validate_version(self, version_list, module_name):
        """Validate version dict format."""

        is_list = isinstance(version_list, list)

        # Must be a list
        if not is_list:
            raise ProtocolDefinitionValidationError(
                "Versions definition is not of type list"
            )

        # Must have at least one definition
        if len(version_list) < 1:
            raise ProtocolDefinitionValidationError(
                "Versions list must define at least one version module"
            )

        if not all(isinstance(v, dict) for v in version_list):
            raise ProtocolDefinitionValidationError(
                "Element of versions definition list is not of type dict"
            )

        for version_dict in version_list:
            # Dicts must have correct format
            try:
                if not (
                    isinstance(version_dict["major_version"], int)
                    and isinstance(version_dict["minimum_minor_version"], int)
                    and isinstance(version_dict["current_minor_version"], int)
                    and isinstance(version_dict["path"], str)
                ):
                    raise ProtocolDefinitionValidationError(
                        "Unexpected types in version definition"
                    )
            except KeyError as e:
                raise ProtocolDefinitionValidationError(
                    f"Element of versions definition list is missing an attribute: {e}"
                )

            # Version number cannot be negative
            if (
                version_dict["major_version"] < 0
                or version_dict["minimum_minor_version"] < 0
                or version_dict["current_minor_version"] < 0
            ):
                raise ProtocolDefinitionValidationError(
                    "Version number cannot be negative"
                )

            # Minimum minor version cannot be great than current version
            if (
                version_dict["minimum_minor_version"]
                > version_dict["current_minor_version"]
            ):
                raise ProtocolDefinitionValidationError(
                    "Minimum supported minor version cannot "
                    "be greater than current minor version"
                )

            # There can only be one definition per major version
            major_version = version_dict["major_version"]
            count = 0
            for version_dict_outer in version_list:
                if version_dict_outer["major_version"] == major_version:
                    count += 1
            if count > 1:
                raise ProtocolDefinitionValidationError(
                    "There can only be one definition per major version. "
                    f"Found {count} for major version {major_version}."
                )

            # Specified module must be loadable
            version_path = version_dict["path"]
            mod = ClassLoader.load_module(version_path, module_name)

            if not mod:
                raise ProtocolDefinitionValidationError(
                    f"Version module path is not loadable: {module_name}, {version_path}"
                )

        return True

    def register_plugin(self, module_name: str) -> Optional[ModuleType]:
        """Register a plugin module."""
        if self._is_already_registered(module_name):
            return self._plugins.get(module_name)

        if self._is_blocked(module_name):
            return None

        mod = self._load_module(module_name)
        if not mod:
            LOGGER.error("Module doesn't exist: %s", module_name)
            return None

        if self._is_valid_plugin(mod, module_name):
            self._plugins[module_name] = mod
            LOGGER.debug("Registered plugin: %s", module_name)
            return mod

        LOGGER.warning("Failed to register plugin: %s", module_name)
        return None

    def _is_already_registered(self, module_name: str) -> bool:
        """Check if the plugin is already registered."""
        if module_name in self._plugins:
            LOGGER.debug("Plugin %s is already registered.", module_name)
            return True
        return False

    def _is_blocked(self, module_name: str) -> bool:
        """Check if the plugin is in the blocklist."""
        if module_name in self._blocklist:
            LOGGER.debug("Blocked %s from loading due to blocklist.", module_name)
            return True
        return False

    def _load_module(self, module_name: str) -> Optional[ModuleType]:
        """Load the plugin module using ClassLoader."""
        try:
            mod = ClassLoader.load_module(module_name)
            return mod
        except ModuleLoadError as e:
            LOGGER.error("Error loading plugin module '%s': %s", module_name, e)
        return None

    def _is_valid_plugin(self, mod: ModuleType, module_name: str) -> bool:
        """Validate the plugin based on various criteria."""
        # Check if the plugin has a 'setup' method
        if hasattr(mod, "setup"):
            return True

        # Check for 'routes' or 'message_types' modules
        # This makes an exception for non-protocol modules that contain admin routes
        # and for old-style protocol modules without version support
        routes = ClassLoader.load_module("routes", module_name)
        message_types = ClassLoader.load_module("message_types", module_name)
        if routes or message_types:
            return True

        # Check for 'definition' module with 'versions' attribute
        definition = ClassLoader.load_module("definition", module_name)
        if not definition:
            LOGGER.error(
                "Protocol does not include 'definition.py' for module: %s",
                module_name,
            )
            return False

        if not hasattr(definition, "versions"):
            LOGGER.error(
                "Protocol definition does not include versions attribute for module: %s",
                module_name,
            )
            return False

        # Validate the 'versions' attribute
        try:
            self.validate_version(definition.versions, module_name)
            return True
        except ProtocolDefinitionValidationError as e:
            LOGGER.error(
                "Protocol versions definition is malformed for module '%s': %s",
                module_name,
                e,
            )
            return False

    def register_package(self, package_name: str) -> Sequence[ModuleType]:
        """Register all modules (sub-packages) under a given package name."""
        LOGGER.debug("Registering package: %s", package_name)
        try:
            module_names = ClassLoader.scan_subpackages(package_name)
        except ModuleLoadError:
            LOGGER.error("Plugin module package not found: %s", package_name)
            module_names = []

        registered_plugins = []
        for module_name in module_names:
            # Skip any module whose last segment is 'tests'
            if module_name.split(".")[-1] == "tests":
                continue

            plugin = self.register_plugin(module_name)
            if plugin:
                registered_plugins.append(plugin)
            else:
                LOGGER.warning(
                    "Failed to register %s under %s", module_name, package_name
                )

        return registered_plugins

    async def init_context(self, context: InjectionContext) -> None:
        """Call plugin setup methods on the current context."""
        LOGGER.debug("Initializing plugin context for %d plugins", len(self._plugins))

        for plugin in self._plugins.values():
            if hasattr(plugin, "setup"):
                await plugin.setup(context)
            else:
                await self.load_protocols(context, plugin)

        # register event handlers for each protocol, if provided
        self.register_protocol_events(context)

    async def load_protocol_version(
        self,
        context: InjectionContext,
        mod: ModuleType,
        version_definition: Optional[dict] = None,
    ) -> None:
        """Load a particular protocol version."""
        protocol_registry = context.inject(ProtocolRegistry)
        goal_code_registry = context.inject(GoalCodeRegistry)

        if hasattr(mod, "MESSAGE_TYPES"):
            protocol_registry.register_message_types(
                mod.MESSAGE_TYPES, version_definition=version_definition
            )

        if hasattr(mod, "CONTROLLERS"):
            protocol_registry.register_controllers(mod.CONTROLLERS)
            goal_code_registry.register_controllers(mod.CONTROLLERS)

    async def load_protocols(self, context: InjectionContext, plugin: ModuleType) -> None:
        """For modules that don't implement setup, register protocols manually."""
        plugin_name = plugin.__name__

        # If this module contains message_types, then assume that
        # this is a valid module of the old style (not versioned)
        try:
            message_types_path = f"{plugin_name}.message_types"
            mod = ClassLoader.load_module(message_types_path)
        except ModuleLoadError as e:
            LOGGER.error("Error loading plugin module message types: %s", e)
            return

        if mod:
            await self.load_protocol_version(context, mod)
        else:
            # Otherwise, try check for definition.py for versioned protocol packages
            try:
                definition_path = f"{plugin_name}.definition"
                definition = ClassLoader.load_module(definition_path)
            except ModuleLoadError as e:
                LOGGER.error("Error loading plugin definition module: %s", e)
                return

            if definition:
                for protocol_version in definition.versions:
                    version_path = (
                        f"{plugin_name}.{protocol_version['path']}.message_types"
                    )
                    try:
                        mod = ClassLoader.load_module(version_path)
                    except ModuleLoadError as e:
                        LOGGER.error(
                            "Error loading plugin module message types from %s: %s",
                            version_path,
                            e,
                        )
                        return

                    if mod:
                        await self.load_protocol_version(context, mod, protocol_version)
                    else:
                        LOGGER.debug("Failed to load %s", version_path)

    async def register_admin_routes(self, app) -> None:
        """Call route registration methods on the current context."""
        LOGGER.debug("Registering admin routes for %d plugins", len(self._plugins))

        for plugin in self._plugins.values():
            plugin_name = plugin.__name__
            mod = None
            definition = ClassLoader.load_module("definition", plugin_name)
            if definition:
                # Load plugin routes that are in a versioned package.
                for plugin_version in definition.versions:
                    version_path = f"{plugin_name}.{plugin_version['path']}.routes"
                    try:
                        mod = ClassLoader.load_module(version_path)
                    except ModuleLoadError as e:
                        LOGGER.error(
                            "Error loading admin routes from %s: %s", version_path, e
                        )
                        continue

                    if mod and hasattr(mod, "register"):
                        await mod.register(app)
            else:
                # Load plugin routes that aren't in a versioned package.
                routes_path = f"{plugin_name}.routes"
                try:
                    mod = ClassLoader.load_module(routes_path)
                except ModuleLoadError as e:
                    LOGGER.error("Error loading admin routes from %s: %s", routes_path, e)
                    continue

                if mod and hasattr(mod, "register"):
                    await mod.register(app)

    def register_protocol_events(self, context: InjectionContext) -> None:
        """Call route register_events methods on the current context."""
        LOGGER.debug("Registering protocol events for %d plugins", len(self._plugins))

        event_bus = context.inject_or(EventBus)
        if not event_bus:
            LOGGER.error("No event bus in context")
            return

        for plugin in self._plugins.values():
            plugin_name = plugin.__name__
            mod = None
            definition = ClassLoader.load_module("definition", plugin_name)
            if definition:
                # Load plugin routes that are in a versioned package.
                for plugin_version in definition.versions:
                    version_path = f"{plugin_name}.{plugin_version['path']}.routes"
                    try:
                        mod = ClassLoader.load_module(version_path)
                    except ModuleLoadError as e:
                        LOGGER.error("Error loading events from %s: %s", version_path, e)
                        continue

                    if mod and hasattr(mod, "register_events"):
                        mod.register_events(event_bus)
            else:
                # Load plugin routes that aren't in a versioned package.
                routes_path = f"{plugin_name}.routes"
                try:
                    mod = ClassLoader.load_module(routes_path)
                except ModuleLoadError as e:
                    LOGGER.error("Error loading events from %s: %s", routes_path, e)
                    continue

                if mod and hasattr(mod, "register_events"):
                    mod.register_events(event_bus)

    def post_process_routes(self, app) -> None:
        """Call route binary file response OpenAPI fixups if applicable."""
        LOGGER.debug("Post-processing routes for %d plugins", len(self._plugins))

        for plugin in self._plugins.values():
            plugin_name = plugin.__name__
            mod = None
            definition = ClassLoader.load_module("definition", plugin_name)
            if definition:
                # Set binary file responses for routes that are in a versioned package.
                for plugin_version in definition.versions:
                    version_path = f"{plugin_name}.{plugin_version['path']}.routes"
                    try:
                        mod = ClassLoader.load_module(version_path)
                    except ModuleLoadError as e:
                        LOGGER.error("Error loading routes from %s: %s", version_path, e)
                        continue

                    if mod and hasattr(mod, "post_process_routes"):
                        mod.post_process_routes(app)
            else:
                # Set binary file responses for routes not in a versioned package.
                routes_path = f"{plugin_name}.routes"
                try:
                    mod = ClassLoader.load_module(routes_path)
                except ModuleLoadError as e:
                    LOGGER.error("Error loading routes from %s: %s", routes_path, e)
                    continue

                if mod and hasattr(mod, "post_process_routes"):
                    mod.post_process_routes(app)

    def __repr__(self) -> str:
        """Return a string representation for this class."""
        return "<{}>".format(self.__class__.__name__)
