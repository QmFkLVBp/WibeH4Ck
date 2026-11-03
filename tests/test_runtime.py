"""Regression checks for sessions, option handling and PoC lifecycles.

External PoCs, package installs and target HTTP requests are mocked.
Session tests use local sockets and subprocess tests use harmless Python code.
"""
import ast
import contextlib
import io
import os
from pathlib import Path
import queue
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import framework
from modules.cve_2019_11043 import CVE201911043
from modules.cve_2024_4577 import CVE20244577
from modules.log4shell import Log4Shell
from modules.revshell import RevShell
import poc_support
from sessions import Session, SessionManager

ROOT = Path(__file__).resolve().parents[1]


def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("Timed out waiting for local worker")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.manager = SessionManager()
        self.addCleanup(self.manager.close)

    def connected(self):
        local, peer = socket.socketpair()
        peer.settimeout(2)
        self.addCleanup(peer.close)
        return self.manager.add(local, "local test"), peer

    def test_background_keeps_socket_and_buffer_for_reattach(self):
        session, peer = self.connected()
        session.interact(io.StringIO("background\n"), io.StringIO())
        self.assertFalse(session.closed.is_set())
        peer.sendall(b"while detached\n")
        until(lambda: bool(session._buffer))
        output = io.StringIO()
        session.interact(io.StringIO("hello\nbackground\n"), output)
        self.assertIn("while detached", output.getvalue())
        self.assertEqual(peer.recv(128), b"hello\n")
        self.assertIs(self.manager.get(session.id), session)
        self.assertFalse(session.closed.is_set())

    def test_ctrl_c_detaches_and_eof_marks_connection_closed(self):
        session, peer = self.connected()
        with patch("sessions.select.select", side_effect=KeyboardInterrupt):
            session.interact(output_stream=io.StringIO())
        self.assertFalse(session.closed.is_set())
        peer.close()
        self.assertTrue(session.closed.wait(2))

    def test_listener_accepts_multiple_sessions_without_terminal_input(self):
        with patch("sessions.sys.stdin") as stdin:
            listener = self.manager.listen("127.0.0.1", 0)
            peers = [socket.create_connection(("127.0.0.1", listener.port)) for _ in range(2)]
            for peer in peers:
                self.addCleanup(peer.close)
            first, second = listener.wait(2), listener.wait(2)
            self.assertNotEqual(first.id, second.id)
            stdin.readline.assert_not_called()
            self.manager.stop_listener(listener.id)
            self.assertFalse(listener._thread.is_alive())
            peers[0].sendall(b"still connected")
            until(lambda: bool(first._buffer))
            self.assertEqual(first.read_pending()[0], b"still connected")
            self.manager.close()
            self.assertTrue(first.closed.is_set())
            self.assertTrue(second.closed.is_set())
            self.assertFalse(first._thread.is_alive())

    def test_closed_port_and_unknown_ids_are_reported(self):
        listener = self.manager.listen("127.0.0.1", 0)
        with self.assertRaises(OSError):
            self.manager.listen("127.0.0.1", listener.port)
        with self.assertRaisesRegex(ValueError, "No session"):
            self.manager.get(999)
        with self.assertRaisesRegex(ValueError, "No listener"):
            self.manager.stop_listener(999)

    def test_detached_buffer_has_a_limit_and_reports_discarded_bytes(self):
        local, peer = socket.socketpair()
        self.addCleanup(peer.close)
        session = Session(1, local, "test", buffer_limit=32)
        self.addCleanup(session.close)
        peer.sendall(b"A" * 100)
        until(lambda: session._dropped == 68)
        data, dropped = session.read_pending()
        self.assertEqual((data, dropped), (b"A" * 32, 68))


class ValidationTests(unittest.TestCase):
    def test_instances_do_not_share_option_values(self):
        first, second = RevShell(), RevShell()
        first.set("LHOST", "127.0.0.1")
        self.assertIsNone(second.get("LHOST"))

    def test_unset_restores_optional_defaults_and_clears_required_values(self):
        mod = RevShell()
        mod.set("LHOST", "127.0.0.1")
        mod.set("TYPE", "PYTHON")
        mod.unset("TYPE")
        self.assertEqual(mod.get("TYPE"), "bash")
        self.assertEqual(mod.validate(), [])
        self.assertIn("bash -i", mod.payload())
        mod.unset("LHOST")
        self.assertIn("missing LHOST", mod.validate())

    def test_invalid_values_do_not_replace_good_settings(self):
        mod = RevShell()
        for key, value in (("LPORT", "0"), ("LPORT", "65536"), ("TYPE", "typo"),
                           ("LHOST", "999.999.1.2"), ("LHOST", "127.0.0.1;id")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                mod.set(key, value)
        self.assertEqual(mod.get("LPORT"), "4444")
        self.assertEqual(mod.get("TYPE"), "bash")

    def test_urls_require_scheme_and_valid_host_port(self):
        mod = CVE20244577()
        for value in ("localhost", "http://", "http://bad host/", "http://host:0/",
                      "http://host:99999/", "file:///tmp/a", "http://-bad/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.set("TARGET", value)
        mod.set("TARGET", "http://127.0.0.1:8080/test/")
        self.assertEqual(mod.get("TARGET"), "http://127.0.0.1:8080/test/")

    def test_cli_bad_options_exit_nonzero_without_traceback(self):
        for args in (("-m", "revshell", "-o", "TYPO=1"),
                     ("-m", "revshell", "-o", "LHOST"), ("-o", "LHOST=127.0.0.1")):
            result = subprocess.run([sys.executable, "rce.py", *args], cwd=ROOT,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("Traceback", result.stderr)

    def test_direct_mode_reports_module_failure_and_closes_resources(self):
        registry = MagicMock()
        registry.modules = {"demo": MagicMock()}
        registry.modules["demo"].validate.return_value = []
        registry.modules["demo"].run.side_effect = RuntimeError("child failed")
        with patch("framework.Registry", return_value=registry), \
                patch.object(sys, "argv", ["rce.py", "-m", "demo"]), \
                contextlib.redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as exit_error:
                framework.main()
        self.assertEqual(exit_error.exception.code, 1)
        self.assertIn("child failed", error.getvalue())
        registry.sessions.close.assert_called_once()

    def test_python_payload_is_valid_python_without_execution(self):
        mod = RevShell()
        mod.set("LHOST", "127.0.0.1")
        mod.set("TYPE", "python")
        command = shlex.split(mod.payload())
        ast.parse(command[2])


class PocSupportTests(unittest.TestCase):
    def test_readiness_checks_real_loopback_port(self):
        process = MagicMock()
        process.poll.return_value = None
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            poc_support.wait_for_ports(process, [port], timeout=1)
            with self.assertRaisesRegex(RuntimeError, "busy"):
                poc_support.check_free_ports([port])

    def test_dead_process_fails_readiness_immediately(self):
        process = MagicMock(returncode=3)
        process.poll.return_value = 3
        with patch("poc_support.socket.create_connection") as connect:
            with self.assertRaisesRegex(RuntimeError, "startup: 3"):
                poc_support.wait_for_ports(process, [1389])
            connect.assert_not_called()

    def test_nonzero_subprocess_exit_is_not_silently_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "code 7"):
            poc_support.run_checked([sys.executable, "-c", "raise SystemExit(7)"], capture_output=True)

    def test_failed_clone_leaves_no_broken_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "poc"
            with patch("poc_support.run_checked", side_effect=RuntimeError("clone failed")):
                with self.assertRaisesRegex(RuntimeError, "clone failed"):
                    poc_support.ensure_repo("unused", work, "main.py")
            self.assertFalse(work.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_existing_checkout_still_gets_environment_setup(self):
        mod = CVE20244577()
        mod.set("TARGET", "http://example.invalid/path/")
        with patch("modules.cve_2024_4577.ensure_repo"), \
                patch("modules.cve_2024_4577.python_environment", return_value="/isolated/python") as env, \
                patch("modules.cve_2024_4577.run_checked") as run:
            mod.run()
        env.assert_called_once()
        self.assertEqual(run.call_args.args[0],
                         ["/isolated/python", "exploit.py", "--url", "http://example.invalid/path/"])

    def test_failed_pip_install_is_retried_and_not_stamped(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            python = work / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            python.parent.mkdir(parents=True)
            python.touch()
            (work / "requirements.txt").write_text("test-only-package\n")
            stamp = work / ".venv/.requirements.sha256"
            with patch("poc_support.run_checked", side_effect=RuntimeError("pip failed")):
                with self.assertRaisesRegex(RuntimeError, "pip failed"):
                    poc_support.python_environment(work)
            self.assertFalse(stamp.exists())
            with patch("poc_support.run_checked") as install:
                poc_support.python_environment(work)
                install.assert_called_once()
            self.assertTrue(stamp.exists())
            with patch("poc_support.run_checked") as install:
                poc_support.python_environment(work)
                install.assert_not_called()

    def test_venv_interpreter_really_uses_venv(self):
        with tempfile.TemporaryDirectory() as tmp:
            interpreter = poc_support.python_environment(Path(tmp))
            result = subprocess.run([interpreter, "-c", "import sys; print(sys.prefix)"],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(Path(result.stdout.strip()), Path(tmp) / ".venv")

    def test_php_fpm_keeps_positional_target_argument(self):
        mod = CVE201911043()
        mod.set("TARGET", "http://example.invalid/index.php")
        with patch("modules.cve_2019_11043.require", return_value=[]), \
                patch("modules.cve_2019_11043.ensure_repo"), \
                patch("modules.cve_2019_11043.run_checked") as run:
            mod.run()
        self.assertEqual(run.call_args.args[0], ["go", "run", ".", mod.get("TARGET")])

    @unittest.skipUnless(os.name == "posix", "POSIX process groups")
    def test_stop_process_terminates_parent_and_child(self):
        program = (
            "import subprocess,sys,signal,time;"
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
            "signal.signal(signal.SIGTERM,lambda *_:(child.wait(),sys.exit(0)));"
            "print(child.pid,flush=True);time.sleep(60)"
        )
        parent = subprocess.Popen([sys.executable, "-c", program], start_new_session=True,
                                  stdout=subprocess.PIPE, text=True)
        self.addCleanup(parent.stdout.close)
        self.addCleanup(lambda: poc_support.stop_process(parent) if parent.poll() is None else None)
        child_pid = int(parent.stdout.readline())
        poc_support.stop_process(parent)
        self.assertIsNotNone(parent.poll())
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)


class Log4ShellTests(unittest.TestCase):
    def configured(self):
        mod = Log4Shell()
        mod.set("TARGET", "http://example.invalid")
        mod.set("LHOST", "127.0.0.1")
        mod.sessions = MagicMock()
        return mod

    @contextlib.contextmanager
    def stubbed(self, mod, readiness_error=None, spawn_error=None):
        events = []
        listener = MagicMock(id=1)
        mod.sessions.listen.side_effect = lambda **kw: (events.append("listen"), listener)[1]
        process = MagicMock()
        process.poll.return_value = None
        def spawn(*args, **kwargs):
            events.append("spawn")
            if spawn_error:
                raise spawn_error
            return process
        def ready(*args):
            events.append("ready")
            if readiness_error:
                raise readiness_error
        def request(*args, **kwargs):
            events.append("http")
            return MagicMock()
        with patch("modules.log4shell.ensure_repo"), patch.object(mod, "_prepare_java"), \
                patch("modules.log4shell.python_environment", return_value="/isolated/python"), \
                patch("modules.log4shell.check_free_ports"), \
                patch("modules.log4shell.subprocess.Popen", side_effect=spawn), \
                patch("modules.log4shell.wait_for_ports", side_effect=ready), \
                patch("modules.log4shell.urllib.request.urlopen", side_effect=request) as http, \
                patch("modules.log4shell.stop_process") as stop:
            yield events, listener, process, stop, http

    def test_listener_is_ready_before_request_and_detach_preserves_session(self):
        mod = self.configured()
        with self.stubbed(mod) as (events, listener, process, stop, http):
            mod.run()
        self.assertEqual(events, ["listen", "spawn", "ready", "http"])
        listener.wait.return_value.interact.assert_called_once()
        listener.wait.return_value.close.assert_not_called()
        mod.sessions.stop_listener.assert_called_once_with(1)
        stop.assert_called_once_with(process)

    def test_startup_failure_stops_listener_and_process_without_http(self):
        mod = self.configured()
        with self.stubbed(mod, readiness_error=RuntimeError("not ready")) as values:
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                mod.run()
        _, _, process, stop, http = values
        stop.assert_called_once_with(process)
        http.assert_not_called()
        mod.sessions.stop_listener.assert_called_once_with(1)

    def test_spawn_failure_closes_bound_listener(self):
        mod = self.configured()
        with self.stubbed(mod, spawn_error=OSError("cannot spawn")) as values:
            with self.assertRaisesRegex(OSError, "cannot spawn"):
                mod.run()
        values[3].assert_not_called()
        mod.sessions.stop_listener.assert_called_once_with(1)

    def test_callback_timeout_cleans_up(self):
        mod = self.configured()
        mod.set("TIMEOUT", "1")
        with self.stubbed(mod) as values:
            values[1].wait.side_effect = queue.Empty
            with patch("modules.log4shell.time.monotonic", side_effect=[0, 2]):
                with self.assertRaisesRegex(RuntimeError, "No connection"):
                    mod.run()
        values[3].assert_called_once_with(values[2])

    def test_port_conflicts_and_invalid_header_are_rejected(self):
        mod = self.configured()
        mod.set("LPORT", "1389")
        mod.set("HEADER", "Invalid Header")
        errors = mod.validate()
        self.assertTrue(any("must be different" in error for error in errors))
        self.assertTrue(any("header name" in error for error in errors))

    @unittest.skipUnless(os.name == "posix", "upstream JDK layout")
    def test_java_selection_matches_upstream_hardcoded_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work, jdk = root / "poc", root / "jdk"
            work.mkdir()
            (jdk / "bin").mkdir(parents=True)
            for binary in ("java", "javac"):
                path = jdk / "bin" / binary
                path.touch()
                path.chmod(0o755)
            mod = self.configured()
            mod.set("JAVA", str(jdk / "bin/java"))
            mod.set("JAVAC", str(jdk / "bin/javac"))
            versions = [subprocess.CompletedProcess([], 0, '', 'java version "1.8.0_20"'),
                        subprocess.CompletedProcess([], 0, 'javac 1.8.0_20', '')]
            with patch("modules.log4shell.WORK_DIR", work), \
                    patch("modules.log4shell.run_checked", side_effect=versions):
                mod._prepare_java()
            self.assertEqual((work / "jdk1.8.0_20").resolve(), jdk)


POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


class PowerShellTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, "PowerShell is not installed on this test host")
    def test_payload_exchanges_a_harmless_expression_over_loopback(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(10)
            mod = RevShell()
            mod.set("LHOST", "127.0.0.1")
            mod.set("LPORT", str(server.getsockname()[1]))
            mod.set("TYPE", "powershell")
            command = shlex.split(mod.payload())
            process = subprocess.Popen([POWERSHELL, *command[1:]],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(10)
                    data = b""
                    while b"PS> " not in data:
                        chunk = connection.recv(4096)
                        self.assertTrue(chunk)
                        data += chunk
                    connection.sendall(b"1+1\n")
                    data = b""
                    while b"PS> " not in data:
                        chunk = connection.recv(4096)
                        self.assertTrue(chunk)
                        data += chunk
                    self.assertIn(b"2", data)
                process.wait(timeout=5)
                self.assertEqual(process.returncode, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
