import contextlib
import logging
from io import BufferedReader, StringIO, TextIOWrapper
from tempfile import NamedTemporaryFile
from unittest import IsolatedAsyncioTestCase, mock

from ..logging import configurator as test_module
from ..logging import utils


class TestLoggingConfigurator(IsolatedAsyncioTestCase):
    agent_label_arg_value = "Aries Cloud Agent"
    transport_arg_value = "transport"
    host_arg_value = "host"
    port_arg_value = "port"

    @mock.patch.object(test_module, "load_resource", autospec=True)
    @mock.patch.object(test_module, "fileConfig", autospec=True)
    def test_configure_default(self, mock_file_config, mock_load_resource):
        test_module.LoggingConfigurator.configure()

        mock_load_resource.assert_called_once_with(
            test_module.DEFAULT_LOGGING_CONFIG_PATH_INI, "utf-8"
        )
        mock_file_config.assert_called_once_with(
            mock_load_resource.return_value,
            disable_existing_loggers=False,
            new_file_path=None,
        )

    def test_configure_default_with_log_file_error_level(self):
        log_file = NamedTemporaryFile()
        with mock.patch.object(
            test_module, "load_resource", mock.MagicMock()
        ) as mock_load:
            mock_load.return_value = None
            test_module.LoggingConfigurator.configure(
                log_level="ERROR", log_file=log_file.name
            )

    @mock.patch.object(test_module, "load_resource", autospec=True)
    @mock.patch.object(test_module, "fileConfig", autospec=True)
    def test_configure_default_with_path(self, mock_file_config, mock_load_resource):
        path = "a path"
        test_module.LoggingConfigurator.configure(path)

        mock_load_resource.assert_called_once_with(path, "utf-8")
        mock_file_config.assert_called_once_with(
            mock_load_resource.return_value,
            disable_existing_loggers=False,
            new_file_path=None,
        )

    def test_configure_multitenant(self):
        with mock.patch.object(
            test_module,
            "logging",
            mock.MagicMock(
                basicConfig=mock.MagicMock(),
                FileHandler=mock.MagicMock(),
                root=mock.MagicMock(
                    warning=mock.MagicMock(),
                    handlers=[],
                ),
            ),
        ):
            test_module.LoggingConfigurator.configure(
                log_file="test.log",
                multitenant=True,
            )

    def test_configure_with_multitenant_with_yaml_file(self):
        with mock.patch.object(
            test_module,
            "logging",
            mock.MagicMock(
                basicConfig=mock.MagicMock(),
                FileHandler=mock.MagicMock(),
                root=mock.MagicMock(
                    warning=mock.MagicMock(),
                    handlers=[],
                ),
            ),
        ):
            test_module.LoggingConfigurator.configure(
                log_config_path="acapy_agent/config/logging/default_multitenant_logging_config.yml",
                log_file="test.log",
                multitenant=True,
            )

    def test_banner_did(self):
        stdout = StringIO()
        mock_http = mock.MagicMock(scheme="http", host="1.2.3.4", port=8081)
        mock_https = mock.MagicMock(schemes=["https", "archie"])
        mock_admin_server = mock.MagicMock(host="1.2.3.4", port=8091)
        with contextlib.redirect_stdout(stdout):
            test_label = "Aries Cloud Agent"
            test_did = "55GkHamhTU1ZbTbV2ab9DE"
            test_module.LoggingConfigurator.print_banner(
                test_label,
                {"in": mock_http},
                {"out": mock_https},
                test_did,
                mock_admin_server,
            )
            test_module.LoggingConfigurator.print_banner(
                test_label, {"in": mock_http}, {"out": mock_https}, test_did
            )
        output = stdout.getvalue()
        assert test_did in output

    def test_load_resource(self):
        # Testing local file access
        with mock.patch("builtins.open", mock.MagicMock()) as mock_open:
            # First call succeeds
            file_handle = mock.MagicMock(spec=TextIOWrapper)
            mock_open.return_value = file_handle
            result = test_module.load_resource("abc", encoding="utf-8")
            mock_open.assert_called_once_with("abc", encoding="utf-8")
            assert result == file_handle  # Verify the returned file handle

            mock_open.reset_mock()
            # Simulate IOError on second call
            mock_open.side_effect = IOError("insufficient privilege")
            # load_resource should absorb IOError
            result = test_module.load_resource("abc", encoding="utf-8")
            mock_open.assert_called_once_with("abc", encoding="utf-8")
            assert result is None

        # Testing package resource access with encoding (text mode)
        with (
            mock.patch("importlib.resources.files") as mock_files,
            mock.patch("io.TextIOWrapper", mock.MagicMock()) as mock_text_io_wrapper,
        ):
            # Setup the mocks
            mock_resource_path = mock.MagicMock()
            mock_files.return_value.joinpath.return_value = mock_resource_path
            mock_resource_handle = mock.MagicMock(spec=BufferedReader)
            mock_resource_path.open.return_value = mock_resource_handle
            mock_text_io_wrapper.return_value = mock.MagicMock(spec=TextIOWrapper)

            result = test_module.load_resource("abc:def", encoding="utf-8")

            # Assertions
            mock_files.assert_called_once_with("abc")
            mock_files.return_value.joinpath.assert_called_once_with("def")
            mock_resource_path.open.assert_called_once_with("rb")
            mock_text_io_wrapper.assert_called_once_with(
                mock_resource_handle, encoding="utf-8"
            )
            assert result is mock_text_io_wrapper.return_value

        # Testing package resource access without encoding (binary mode)
        with mock.patch("importlib.resources.files") as mock_files:
            # Setup the mocks
            mock_resource_path = mock.MagicMock()
            mock_files.return_value.joinpath.return_value = mock_resource_path
            mock_resource_handle = mock.MagicMock(spec=BufferedReader)
            mock_resource_path.open.return_value = mock_resource_handle

            result = test_module.load_resource("abc:def", encoding=None)

            # Assertions
            mock_files.assert_called_once_with("abc")
            mock_files.return_value.joinpath.assert_called_once_with("def")
            mock_resource_path.open.assert_called_once_with("rb")
            assert result == mock_resource_handle  # Verify the returned binary stream


class TestLoggingUtils(IsolatedAsyncioTestCase):
    def setUp(self):
        """Set up test environment by backing up logging states and resetting TRACE level."""
        # Backup existing logging attributes (e.g., DEBUG, INFO)
        self.original_levels = {
            attr: getattr(logging, attr) for attr in dir(logging) if attr.isupper()
        }

        # Backup existing logger class methods (e.g., debug, info)
        self.original_logger_methods = {
            attr: getattr(logging.getLoggerClass(), attr, None)
            for attr in dir(logging.getLoggerClass())
            if not attr.startswith("_")
        }

        # Remove TRACE level and 'trace' method if they exist
        if hasattr(logging, "TRACE"):
            delattr(logging, "TRACE")
        if hasattr(logging.getLoggerClass(), "trace"):
            delattr(logging.getLoggerClass(), "trace")

        # Patch the TRACE_LEVEL_ADDED flag to False before each test
        self.trace_level_added_patcher = mock.patch(
            "acapy_agent.config.logging.utils._TRACE_LEVEL_ADDED", False
        )
        self.mock_trace_level_added = self.trace_level_added_patcher.start()

    def tearDown(self):
        """Restore original logging states after each test."""
        # Stop patching TRACE_LEVEL_ADDED
        self.trace_level_added_patcher.stop()

        # Restore original logging level attributes
        for attr, value in self.original_levels.items():
            setattr(logging, attr, value)

        # Identify and remove any new uppercase attributes added during tests (e.g., TRACE)
        current_levels = {attr for attr in dir(logging) if attr.isupper()}
        for attr in current_levels - set(self.original_levels.keys()):
            delattr(logging, attr)

        # Restore original logger class methods
        LoggerClass = logging.getLoggerClass()
        for attr, value in self.original_logger_methods.items():
            if value is not None:
                setattr(LoggerClass, attr, value)
            else:
                if hasattr(LoggerClass, attr):
                    delattr(LoggerClass, attr)

        # Identify and remove any new logger methods added during tests (e.g., trace)
        current_methods = {attr for attr in dir(LoggerClass) if not attr.startswith("_")}
        for attr in current_methods - set(self.original_logger_methods.keys()):
            delattr(LoggerClass, attr)

    @mock.patch("acapy_agent.config.logging.utils.LOGGER")
    @mock.patch("acapy_agent.config.logging.utils.logging.addLevelName")
    def test_add_logging_level_success(self, mock_add_level_name, mock_logger):
        utils.add_logging_level("CUSTOM", 2)

        mock_add_level_name.assert_called_once_with(2, "CUSTOM")
        self.assertTrue(hasattr(logging, "CUSTOM"))
        self.assertEqual(logging.CUSTOM, 2)

        logger = logging.getLogger(__name__)
        self.assertTrue(hasattr(logger, "custom"))
        self.assertTrue(callable(logger.custom))

        self.assertTrue(hasattr(logging, "custom"))
        self.assertTrue(callable(logging.custom))

    def test_add_logging_level_existing_level_name(self):
        # Add a level named 'DEBUG' which already exists
        with self.assertRaises(AttributeError) as context:
            utils.add_logging_level("DEBUG", 15)
        self.assertIn("DEBUG already defined in logging module", str(context.exception))

    def test_add_logging_level_existing_method_name(self):
        # Add a logging method that already exists ('debug')
        with self.assertRaises(AttributeError) as context:
            utils.add_logging_level("CUSTOM", 25, method_name="debug")
        self.assertIn("debug already defined in logging module", str(context.exception))

    @mock.patch("acapy_agent.config.logging.utils.add_logging_level")
    @mock.patch("acapy_agent.config.logging.utils.LOGGER")
    def test_add_trace_level_new(self, mock_logger, mock_add_logging_level):
        # Ensure _TRACE_LEVEL_ADDED is False
        utils.add_trace_level()

        mock_add_logging_level.assert_called_once_with(
            "TRACE", logging.DEBUG - 5, "trace"
        )

        # Verify logger.debug was called
        mock_logger.debug.assert_called_with("%s level added to logging module.", "TRACE")

        # Check that _TRACE_LEVEL_ADDED is now True
        self.assertTrue(utils._TRACE_LEVEL_ADDED)

    @mock.patch("acapy_agent.config.logging.utils.LOGGER")
    @mock.patch(
        "acapy_agent.config.logging.utils.add_logging_level",
        side_effect=AttributeError("TRACE already exists"),
    )
    def test_add_trace_level_already_exists_exception(
        self, mock_add_logging_level, mock_logger
    ):
        utils.add_trace_level()

        # Verify logger.warning was called
        mock_logger.warning.assert_called_with(
            "%s level already exists: %s", "TRACE", mock_add_logging_level.side_effect
        )

    @mock.patch("acapy_agent.config.logging.utils.LOGGER")
    @mock.patch("acapy_agent.config.logging.utils.add_logging_level")
    def test_add_trace_level_already_present(self, mock_add_logging_level, mock_logger):
        # Manually set _TRACE_LEVEL_ADDED to True to simulate already added TRACE level
        with mock.patch("acapy_agent.config.logging.utils._TRACE_LEVEL_ADDED", True):
            utils.add_trace_level()

            # add_logging_level should not be called since TRACE level is already added
            mock_add_logging_level.assert_not_called()

            # Verify logger.debug was not called
            mock_logger.debug.assert_not_called()
