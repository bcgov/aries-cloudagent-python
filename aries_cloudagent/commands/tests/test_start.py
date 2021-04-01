import sys

from asynctest import mock as async_mock, TestCase as AsyncTestCase

from ...config.error import ArgsParseError

from .. import start as test_module


class TestStart(AsyncTestCase):
    def test_bad_args(self):
        with self.assertRaises(SystemExit):
            test_module.execute([])

        with self.assertRaises(SystemExit):
            test_module.execute(["bad"])

    async def test_start_shutdown_app(self):
        mock_conductor = async_mock.MagicMock(
            setup=async_mock.CoroutineMock(),
            start=async_mock.CoroutineMock(),
            stop=async_mock.CoroutineMock(),
        )
        await test_module.start_app(mock_conductor)
        await test_module.shutdown_app(mock_conductor)

    def test_exec_start(self):
        with async_mock.patch.object(
            test_module, "start_app", autospec=True
        ) as start_app, async_mock.patch.object(
            test_module, "run_loop"
        ) as run_loop, async_mock.patch.object(
            test_module, "shutdown_app", autospec=True
        ) as shutdown_app, async_mock.patch.object(
            test_module, "uvloop", async_mock.MagicMock()
        ) as mock_uvloop:
            mock_uvloop.install = async_mock.MagicMock()
            test_module.execute(
                [
                    "-it",
                    "http",
                    "0.0.0.0",
                    "80",
                    "-ot",
                    "http",
                    "--endpoint",
                    "0.0.0.0",
                    "80",
                    "--no-ledger",
                ]
            )
            start_app.assert_called_once()
            assert isinstance(start_app.call_args[0][0], test_module.Conductor)
            shutdown_app.assert_called_once()
            assert isinstance(shutdown_app.call_args[0][0], test_module.Conductor)
            run_loop.assert_called_once()

    async def test_run_loop(self):
        startup = async_mock.CoroutineMock()
        startup_call = startup()
        shutdown = async_mock.CoroutineMock()
        shutdown_call = shutdown()
        with async_mock.patch.object(
            test_module, "asyncio", autospec=True
        ) as mock_asyncio:
            test_module.run_loop(startup_call, shutdown_call)
            mock_add = mock_asyncio.get_event_loop.return_value.add_signal_handler
            mock_add.assert_called_once()
            init_coro = mock_asyncio.ensure_future.call_args[0][0]
            mock_asyncio.get_event_loop.return_value.run_forever.assert_called_once()
            await init_coro
            startup.assert_awaited_once()

            done_calls = (
                mock_asyncio.get_event_loop.return_value.add_signal_handler.call_args
            )
            done_calls[0][1]()  # exec partial
            done_coro = mock_asyncio.ensure_future.call_args[0][0]
            tasks = [
                async_mock.MagicMock(),
                async_mock.MagicMock(cancel=async_mock.MagicMock()),
            ]
            mock_asyncio.gather = async_mock.CoroutineMock()

            if sys.version_info.major == 3 and sys.version_info.minor > 6:
                mock_asyncio.all_tasks.return_value = tasks
                mock_asyncio.current_task.return_value = tasks[0]
            else:
                mock_asyncio.Task.all_tasks.return_value = tasks
                mock_asyncio.Task.current_task.return_value = tasks[0]

            await done_coro
            shutdown.assert_awaited_once()

    async def test_run_loop_init_x(self):
        startup = async_mock.CoroutineMock(side_effect=KeyError("the front fell off"))
        startup_call = startup()
        shutdown = async_mock.CoroutineMock()
        shutdown_call = shutdown()
        with async_mock.patch.object(
            test_module, "asyncio", autospec=True
        ) as mock_asyncio, async_mock.patch.object(
            test_module, "LOGGER", autospec=True
        ) as mock_logger:
            test_module.run_loop(startup_call, shutdown_call)
            mock_add = mock_asyncio.get_event_loop.return_value.add_signal_handler
            mock_add.assert_called_once()
            init_coro = mock_asyncio.ensure_future.call_args[0][0]
            mock_asyncio.get_event_loop.return_value.run_forever.assert_called_once()
            await init_coro
            startup.assert_awaited_once()

            done_calls = (
                mock_asyncio.get_event_loop.return_value.add_signal_handler.call_args
            )
            done_calls[0][1]()  # exec partial
            done_coro = mock_asyncio.ensure_future.call_args[0][0]
            task = async_mock.MagicMock()
            mock_asyncio.gather = async_mock.CoroutineMock()

            if sys.version_info.major == 3 and sys.version_info.minor > 6:
                mock_asyncio.all_tasks.return_value = [task]
                mock_asyncio.current_task.return_value = task
            else:
                mock_asyncio.Task.all_tasks.return_value = [task]
                mock_asyncio.Task.current_task.return_value = task

            await done_coro
            shutdown.assert_awaited_once()
            mock_logger.exception.assert_called_once()

    def test_main(self):
        with async_mock.patch.object(
            test_module, "__name__", "__main__"
        ) as mock_name, async_mock.patch.object(
            test_module, "execute", async_mock.MagicMock()
        ) as mock_execute:
            test_module.main()
            mock_execute.assert_called_once
