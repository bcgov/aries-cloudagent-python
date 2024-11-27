import contextlib
from io import BufferedReader, StringIO, TextIOWrapper
from tempfile import NamedTemporaryFile
from unittest import IsolatedAsyncioTestCase, mock

from ..logging import configurator as test_module


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
