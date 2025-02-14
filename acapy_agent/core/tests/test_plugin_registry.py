from unittest import IsolatedAsyncioTestCase
from unittest.mock import call

import pytest

from acapy_agent.tests import mock

from ...config.injection_context import InjectionContext
from ...utils.classloader import ClassLoader, ModuleLoadError
from ..error import ProtocolDefinitionValidationError
from ..goal_code_registry import GoalCodeRegistry
from ..plugin_registry import PluginRegistry
from ..protocol_registry import ProtocolRegistry


class TestPluginRegistry(IsolatedAsyncioTestCase):
    def setUp(self):
        self.blocked_module = "blocked_module"
        self.registry = PluginRegistry(blocklist=[self.blocked_module])

        self.context = InjectionContext(enforce_typing=False)
        self.proto_registry = mock.MagicMock(
            register_message_types=mock.MagicMock(),
            register_controllers=mock.MagicMock(),
        )
        self.goal_code_registry = mock.MagicMock(
            register_controllers=mock.MagicMock(),
        )
        self.context.injector.bind_instance(ProtocolRegistry, self.proto_registry)
        self.context.injector.bind_instance(GoalCodeRegistry, self.goal_code_registry)

    async def test_setup(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name
        ctx = mock.MagicMock()
        self.registry._plugins[mod_name] = mod
        assert list(self.registry.plugin_names) == [mod_name]
        assert list(self.registry.plugins) == [mod]
        mod.setup = mock.CoroutineMock()
        await self.registry.init_context(ctx)
        mod.setup.assert_awaited_once_with(ctx)

    async def test_register_routes(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name
        app = mock.MagicMock()
        self.registry._plugins[mod_name] = mod
        mod.routes.register = mock.CoroutineMock()
        definition = mock.MagicMock()
        definition.versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
            }
        ]

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[definition, mod.routes]),
        ) as load_module:
            await self.registry.register_admin_routes(app)

            calls = [
                call("definition", mod_name),
                call(f"{mod_name}.{definition.versions[0]['path']}.routes"),
            ]
            load_module.assert_has_calls(calls)
        assert mod.routes.register.call_count == 1

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[definition, ModuleLoadError()]),
        ) as load_module:
            await self.registry.register_admin_routes(app)

            calls = [
                call("definition", mod_name),
                call(f"{mod_name}.{definition.versions[0]['path']}.routes"),
            ]
            load_module.assert_has_calls(calls)
        assert mod.routes.register.call_count == 1

    async def test_register_routes_mod_no_version(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name
        app = mock.MagicMock()
        self.registry._plugins[mod_name] = mod
        mod.routes.register = mock.CoroutineMock()

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[None, mod.routes]),
        ) as load_module:
            await self.registry.register_admin_routes(app)

            calls = [call("definition", mod_name), call(f"{mod_name}.routes")]
            load_module.assert_has_calls(calls)
        assert mod.routes.register.call_count == 1

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[None, ModuleLoadError()]),
        ) as load_module:
            await self.registry.register_admin_routes(app)

            calls = [
                call("definition", mod_name),
                call(f"{mod_name}.routes"),
            ]
            load_module.assert_has_calls(calls)
        assert mod.routes.register.call_count == 1

    async def test_post_process_routes(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name
        app = mock.MagicMock()
        self.registry._plugins[mod_name] = mod
        mod.routes.post_process_routes = mock.MagicMock()
        definition = mock.MagicMock()
        definition.versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
            }
        ]

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[definition, mod.routes]),
        ) as load_module:
            self.registry.post_process_routes(app)

            calls = [
                call("definition", mod_name),
                call(f"{mod_name}.{definition.versions[0]['path']}.routes"),
            ]
            load_module.assert_has_calls(calls)
        assert mod.routes.post_process_routes.call_count == 1

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[definition, ModuleLoadError()]),
        ) as load_module:
            self.registry.post_process_routes(app)

            calls = [
                call("definition", mod_name),
                call(f"{mod_name}.{definition.versions[0]['path']}.routes"),
            ]
            load_module.assert_has_calls(calls)
        assert mod.routes.post_process_routes.call_count == 1

    async def test_post_process_routes_mod_no_version(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name
        app = mock.MagicMock()
        self.registry._plugins[mod_name] = mod
        mod.routes.register = mock.CoroutineMock()

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[None, mod.routes]),
        ) as load_module:
            self.registry.post_process_routes(app)

            calls = [call("definition", mod_name), call(f"{mod_name}.routes")]
            load_module.assert_has_calls(calls)
        assert mod.routes.post_process_routes.call_count == 1

        with mock.patch.object(
            ClassLoader,
            "load_module",
            mock.MagicMock(side_effect=[None, ModuleLoadError()]),
        ) as load_module:
            self.registry.post_process_routes(app)

            calls = [call("definition", mod_name), call(f"{mod_name}.routes")]
            load_module.assert_has_calls(calls)
        assert mod.routes.post_process_routes.call_count == 1

    async def test_validate_version_not_a_list(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions_not_a_list = {}

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions_not_a_list, mod_name)

    async def test_validate_version_list_element_not_an_object(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [{}, []]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_list_element_empty(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = []

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_list_missing_attribute(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                # "path": "v1_0", # missing
            }
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_negative_version(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": -1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
            }
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_min_greater_current(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 1,
                "current_minor_version": 0,
                "path": "v1_0",
            }
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_multiple_major(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
            },
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 1,
                "path": "v1_1",
            },
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_bad_path(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 1,
                "current_minor_version": 0,
                "path": "v1_0",
            }
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock(return_value=None)
        ) as load_module:
            with pytest.raises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_validate_version_list_correct(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
            },
            {
                "major_version": 2,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v2_0",
            },
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            assert self.registry.validate_version(versions, mod_name) is True

            load_module.assert_has_calls(
                [
                    call("v1_0", "test_mod"),
                    call().__bool__(),
                    call("v2_0", "test_mod"),
                    call().__bool__(),
                ]
            )

    async def test_validate_version_list_extra_attributes_ok(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
                "not": "an attribute",
            }
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            assert self.registry.validate_version(versions, mod_name) is True

    async def test_validate_version_no_such_mod(self):
        mod_name = "no_mod"
        mod = mock.MagicMock()
        mod.__name__ = mod_name

        versions = [
            {
                "major_version": 1,
                "minimum_minor_version": 0,
                "current_minor_version": 0,
                "path": "v1_0",
            }
        ]

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.return_value = None

            with self.assertRaises(ProtocolDefinitionValidationError):
                self.registry.validate_version(versions, mod_name)

    async def test_register_plugin_already_present(self):
        mod_name = "test_mod"
        mod = mock.MagicMock()
        self.registry._plugins[mod_name] = mod
        assert mod == self.registry.register_plugin(mod_name)

    async def test_register_plugin_load_x(self):
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = ModuleLoadError("failure to load")
            assert self.registry.register_plugin("dummy") is None

    async def test_register_plugin_no_mod(self):
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.return_value = None
            assert self.registry.register_plugin("dummy") is None

    async def test_register_plugin_no_definition(self):
        class MODULE:
            no_setup = "no setup attr"

        obj = MODULE()
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [
                obj,  # module
                None,  # routes
                None,  # message types
                None,  # definition
            ]
            assert self.registry.register_plugin("dummy") is None

    async def test_register_plugin_no_versions(self):
        class MODULE:
            no_setup = "no setup attr"

        obj = MODULE()
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [
                obj,  # module
                None,  # routes
                None,  # message types
                "str-has-no-versions-attr",  # definition without versions attr
            ]
            assert self.registry.register_plugin("dummy") is None

    async def test_register_plugin_has_setup(self):
        class MODULE:
            setup = "present"

        obj = MODULE()
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [
                obj,  # module
                None,  # routes
                None,  # message types
                None,  # definition without versions attr
            ]
            assert self.registry.register_plugin("dummy") == obj

    async def test_unregister_plugin_has_setup(self):
        class MODULE:
            setup = "present"

        obj = MODULE()
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [
                obj,  # module
                None,  # routes
                None,  # message types
                None,  # definition without versions attr
            ]
            assert self.registry.register_plugin(self.blocked_module) is None
            assert self.blocked_module not in self.registry._plugins.keys()

    async def test_register_definitions_malformed(self):
        class MODULE:
            no_setup = "no setup attr"

        obj = MODULE()
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [
                obj,  # module
                None,  # routes
                None,  # message types
                mock.MagicMock(versions="not-a-list"),
            ]
            assert self.registry.register_plugin("dummy") is None

    async def test_register_package_x(self):
        with mock.patch.object(
            ClassLoader, "scan_subpackages", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = ModuleLoadError()
            assert not self.registry.register_package("dummy")

    async def test_load_protocols_load_x(self):
        mock_plugin = mock.MagicMock(__name__="dummy")
        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = ModuleLoadError()
            await self.registry.load_protocols(None, mock_plugin)
            assert load_module.call_count == 1

    async def test_load_protocols_load_mod(self):
        mock_plugin = mock.MagicMock(__name__="dummy")
        mock_mod = mock.MagicMock()
        mock_mod.MESSAGE_TYPES = mock.MagicMock()
        mock_mod.CONTROLLERS = mock.MagicMock()
        mock_mod.__name__ = "test_mod"

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.return_value = mock_mod
            await self.registry.load_protocols(self.context, mock_plugin)

    async def test_load_protocols_no_mod_load_x(self):
        mock_plugin = mock.MagicMock(__name__="dummy")

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [None, ModuleLoadError()]
            await self.registry.load_protocols(self.context, mock_plugin)
            assert load_module.call_count == 2

    async def test_load_protocols_no_mod_def_no_message_types(self):
        mock_plugin = mock.MagicMock(__name__="dummy")
        mock_def = mock.MagicMock(
            versions=[
                {
                    "major_version": 1,
                    "minimum_minor_version": 0,
                    "current_minor_version": 0,
                    "path": "v1_0",
                }
            ]
        )

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [None, mock_def, ModuleLoadError()]
            await self.registry.load_protocols(self.context, mock_plugin)
            assert load_module.call_count == 3

    async def test_load_protocols_no_mod_def_message_types(self):
        mock_plugin = mock.MagicMock(__name__="dummy")
        mock_def = mock.MagicMock(
            versions=[
                {
                    "major_version": 1,
                    "minimum_minor_version": 0,
                    "current_minor_version": 0,
                    "path": "v1_0",
                },
                {
                    "major_version": 2,
                    "minimum_minor_version": 0,
                    "current_minor_version": 0,
                    "path": "v2_0",
                },
            ]
        )
        mock_mod = mock.MagicMock()
        mock_mod.MESSAGE_TYPES = mock.MagicMock()
        mock_mod.CONTROLLERS = mock.MagicMock()
        mock_mod.__name__ = "test_mod"

        with mock.patch.object(
            ClassLoader, "load_module", mock.MagicMock()
        ) as load_module:
            load_module.side_effect = [None, mock_def, mock_mod, mock_mod]
            await self.registry.load_protocols(self.context, mock_plugin)
            assert load_module.call_count == 4

    def test_repr(self):
        assert isinstance(repr(self.registry), str)
