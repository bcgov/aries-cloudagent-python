"""Sane defaults for known message definitions."""

from .classloader import ClassLoader, ModuleLoadError
from .messaging.protocol_registry import ProtocolRegistry


def default_protocol_registry() -> ProtocolRegistry:
    """Protocol registry for default message types."""
    registry = ProtocolRegistry()

    packages = ClassLoader.scan_subpackages("aries_cloudagent.protocols")
    for pkg in packages:
        try:
            mod = ClassLoader.load_module(pkg + ".message_types")
        except ModuleLoadError:
            continue
        if hasattr(mod, "MESSAGE_TYPES"):
            registry.register_message_types(mod.MESSAGE_TYPES)
        if hasattr(mod, "CONTROLLERS"):
            registry.register_controllers(mod.CONTROLLERS)

    return registry
