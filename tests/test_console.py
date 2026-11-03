"""Console regression checks. No exploit or external PoC is executed."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import framework
from terminal_ui import MODULE_STYLE, Terminal

ANSI = re.compile(r"\x1b\[[0-9;]*m")


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.registry = framework.Registry()
        for mod in self.registry.modules.values():
            mod.options = copy.deepcopy(mod.options)
        self.ui = framework.UI(self.registry)

    def capture(self, action):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            action()
        return ANSI.sub("", out.getvalue())

    def cli(self, *args, input_text=None, extra_env=None):
        env = dict(os.environ, PYTHONWARNINGS="error")
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(ROOT / "rce.py"), *args],
            input=input_text,
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
            timeout=10,
        )

    def test_help_and_list_start_without_name_error_or_warnings(self):
        help_result = self.cli("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("open the console", help_result.stdout)
        self.assertEqual(help_result.stderr, "")
        listing = self.cli("-l")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual(len(listing.stdout.splitlines()), 4)
        self.assertEqual(
            [line.split()[0] for line in listing.stdout.splitlines()],
            sorted(MODULE_STYLE),
        )
        self.assertEqual(listing.stderr, "")

    def test_registry_skips_template_and_package_marker(self):
        self.assertEqual(sorted(self.registry.modules), sorted(MODULE_STYLE))
        self.assertNotIn("myexploit", self.registry.modules)
        self.assertEqual((ROOT / "modules/__init__.py").read_bytes(), b"")
        self.assertEqual(framework.Listener(port=4321).port, 4321)

    def test_all_modules_select_by_name_number_and_path(self):
        for i, (name, module) in enumerate(self.ui._module_items(), 1):
            for selection in (name, str(i), MODULE_STYLE[name]["path"]):
                output = self.capture(lambda: self.ui.use([selection]))
                self.assertIs(self.ui.current, module)
                self.assertIn(name, output)
                self.assertIn("OPTIONS", output)
        self.capture(lambda: self.ui.dispatch("back", []))
        self.assertIsNone(self.ui.current)

    def test_selecting_or_viewing_does_not_run_exploits_or_network(self):
        with (
            patch("subprocess.run") as external,
            patch("socket.socket") as socket_factory,
        ):
            for name, module in self.ui._module_items():
                with patch.object(module, "run") as run:
                    self.capture(lambda: self.ui.use([name]))
                    self.capture(lambda: self.ui.dispatch("info", []))
                    self.capture(lambda: self.ui.show(["options"]))
                    run.assert_not_called()
            external.assert_not_called()
            socket_factory.assert_not_called()

    def test_search_keeps_menu_numbers(self):
        output = self.capture(lambda: self.ui.list_modules("PHP /"))
        self.assertIn("cve_2019_11043", output)
        self.assertIn("cve_2024_4577", output)
        self.assertNotIn("revshell", output)
        empty = self.capture(lambda: self.ui.list_modules("no-such-module"))
        self.assertIn("No modules matched", empty)
        before = self.ui.current
        self.capture(lambda: self.ui.use(["0"]))
        self.assertIs(self.ui.current, before)

    def test_validation_blocks_run_until_required_values_are_set(self):
        self.capture(lambda: self.ui.use(["log4shell"]))
        with patch.object(self.ui.current, "run") as run:
            output = self.capture(self.ui.do_run)
            run.assert_not_called()
            self.assertIn("missing TARGET", output)
            self.assertIn("missing LHOST", output)

    def test_settings_and_unset_update_the_displayed_values(self):
        self.capture(lambda: self.ui.use(["revshell"]))
        self.capture(lambda: self.ui.set_opt(["LHOST", "127.0.0.1"]))
        self.assertEqual(self.ui.current.get("LHOST"), "127.0.0.1")
        self.assertIn(
            "127.0.0.1",
            self.capture(lambda: self.ui.show(["options"])),
        )
        self.capture(lambda: self.ui.unset_opt(["LHOST"]))
        self.assertIsNone(self.ui.current.get("LHOST"))

    def test_completion_understands_module_and_option_context(self):
        fake = MagicMock()
        with patch.object(framework, "readline", fake):
            ui = framework.UI(self.registry)
            completer = fake.set_completer.call_args.args[0]
            fake.get_begidx.return_value = 4
            fake.get_line_buffer.return_value = "use rev"
            self.assertEqual(completer("rev", 0), "revshell")
            ui.current = self.registry.modules["revshell"]
            fake.get_line_buffer.return_value = "set LH"
            self.assertEqual(completer("LH", 0), "LHOST")
            self.assertIsNone(completer("LH", 1))

    def test_banner_glyphs_have_matching_cells_and_styles(self):
        font = json.loads((ROOT / "assets/bloody.json").read_text())
        self.assertIn("4", font["glyphs"])
        for glyph in font["glyphs"].values():
            self.assertEqual(len(glyph), font["height"])
            for text, shades in glyph:
                self.assertEqual(len(text), len(shades))
        output = self.capture(lambda: Terminal(framework.C).art("WIBEH4CK"))
        self.assertIn("█", output)

    def test_tab_binding_supports_gnu_readline_and_libedit(self):
        for backend, binding in (
            ("readline", "tab: complete"),
            ("libedit readline", "bind ^I rl_complete"),
        ):
            fake = MagicMock()
            fake.__doc__ = backend
            with patch.object(framework, "readline", fake):
                framework.UI(self.registry)
                fake.parse_and_bind.assert_called_once_with(binding)

    def test_layout_fits_common_terminal_widths(self):
        for width in (20, 40, 80, 120):
            with patch(
                "terminal_ui.shutil.get_terminal_size",
                return_value=os.terminal_size((width, 40)),
            ):
                actions = [
                    self.ui.banner,
                    self.ui.menu,
                    self.ui.help,
                    self.ui.list_modules,
                ]
                for name in MODULE_STYLE:
                    actions.append(lambda n=name: self.ui.use([n]))
                for action in actions:
                    output = self.capture(action)
                    self.assertTrue(
                        all(
                            len(line) <= width
                            for line in output.splitlines()
                        ),
                        (width, action, output),
                    )

    def test_bad_quote_does_not_exit_console(self):
        result = self.cli(
            "--no-banner", "--no-color",
            input_text='use "broken\nmenu\nexit\n',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No closing quotation", result.stdout)
        self.assertGreaterEqual(result.stdout.count("MODULE MENU"), 2)
        self.assertNotIn("\x1b", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_no_color_and_no_banner_are_honored(self):
        result = self.cli(
            "--no-banner", input_text="exit\n", extra_env={"NO_COLOR": "1"}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\x1b", result.stdout)
        self.assertNotIn("█", result.stdout)
        self.assertIn("MODULE MENU", result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
