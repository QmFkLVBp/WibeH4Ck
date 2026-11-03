#!/usr/bin/env python3
"""framework.py — минималистичное ядро RCE-фреймворка для HTB/THM."""
import sys
import os
import importlib
import copy
import ipaddress
import queue
import argparse
import shlex
import shutil
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from urllib.parse import urlsplit

from terminal_ui import Terminal, module_style
from sessions import Listener, SessionManager, interactive_shell

try:
    import readline
except ImportError:
    readline = None


class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


def require(*bins: str) -> List[str]:
    return [b for b in bins if not shutil.which(b)]


def validate_opt(name: str, value: Any) -> Optional[str]:
    """Простая валидация формата. Возвращает текст ошибки или None."""
    if value is None:
        return None
    v = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in v):
        return f"{name}: control characters are not allowed"
    if name in ("LPORT", "RPORT", "CB_PORT", "HTTP_PORT", "WEBPORT"):
        try:
            port = int(v)
            if not 1 <= port <= 65535:
                return f"{name}: порт вне диапазона 1..65535 ({port})"
        except ValueError:
            return f"{name}: должен быть числом ({v})"
    if name == "TIMEOUT":
        try:
            if not 1 <= int(v) <= 3600:
                return "TIMEOUT: expected 1..3600 seconds"
        except ValueError:
            return "TIMEOUT: expected an integer"
    if name in ("LHOST", "TARGET"):
        if name == "TARGET" and "://" in v:
            try:
                parsed = urlsplit(v)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    return "TARGET: expected an http:// or https:// URL"
                if parsed.username is not None or parsed.password is not None:
                    return "TARGET: embedded URL credentials are not supported"
                if any(char.isspace() for char in v):
                    return "TARGET: spaces must be URL-encoded"
                if parsed.port is not None and not 1 <= parsed.port <= 65535:
                    return "TARGET: invalid port"
                host = parsed.hostname
            except ValueError as exc:
                return f"TARGET: invalid URL ({exc})"
        else:
            host = v
        try:
            address = ipaddress.ip_address(host)
            if name == "LHOST" and address.version != 4:
                return "LHOST: IPv6 callbacks are not supported"
        except ValueError:
            if re.fullmatch(r"[0-9.]+", host):
                return f"{name}: invalid IP address"
            labels = host.rstrip(".").split(".")
            if len(host) > 253 or not all(
                re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label
                )
                for label in labels
            ):
                return f"{name}: invalid hostname/IP"
    return None


class Module:
    name = "base"
    description = ""
    author = ""
    options: Dict[str, Dict[str, Any]] = {}

    def __init__(self):
        self.options = copy.deepcopy(type(self).options)
        self._defaults = {
            key: copy.deepcopy(opt.get("value"))
            for key, opt in self.options.items()
        }
        self.sessions = SessionManager()

    def _option_error(self, key, value):
        spec = self.options[key]
        if value is None or value == "":
            return f"missing {key}" if spec.get("required") else None
        error = validate_opt(key, value)
        if error:
            return error
        if spec.get("kind") == "url" and not str(value).startswith(
            ("http://", "https://")
        ):
            return f"{key}: include http:// or https://"
        choices = spec.get("choices")
        if choices and str(value).lower() not in choices:
            return f"{key}: choose {', '.join(choices)}"
        return None

    def set(self, k: str, v: Any) -> bool:
        if k not in self.options:
            return False
        if isinstance(v, str):
            v = v.strip()
        if self.options[k].get("choices") and isinstance(v, str):
            v = v.lower()
        error = self._option_error(k, v)
        if error:
            raise ValueError(error)
        self.options[k]["value"] = v
        return True

    def get(self, k: str) -> Any:
        value = self.options[k].get("value")
        if value in (None, "") and not self.options[k].get("required"):
            return self._defaults.get(k)
        return value

    def unset(self, k):
        if k not in self.options:
            raise ValueError(f"Unknown option: {k}")
        self.options[k]["value"] = (
            None if self.options[k].get("required")
            else copy.deepcopy(self._defaults[k])
        )

    def validate(self) -> List[str]:
        return [
            error for key in self.options
            if (error := self._option_error(key, self.get(key)))
        ]

    def run(self) -> None:
        raise NotImplementedError

    def info(self) -> None:
        print(f"\n{C.BOLD}{C.CY}Module:{C.END} {self.name}")
        print(f"{C.BOLD}Description:{C.END} {self.description}")
        if self.author:
            print(f"{C.BOLD}Author:{C.END} {self.author}")


class Registry:
    def __init__(self, modules_dir: Optional[Path] = None):
        self.modules_dir = modules_dir or (Path(__file__).parent / "modules")
        self.modules: Dict[str, Module] = {}
        self.sessions = SessionManager()
        self._load()

    def _load(self) -> None:
        if not self.modules_dir.exists():
            print(
                f"{C.R}[!] modules/ not found at {self.modules_dir}{C.END}"
            )
            return
        parent = self.modules_dir.parent
        if str(parent) not in sys.path:
            sys.path.insert(0, str(parent))
        for f in sorted(self.modules_dir.glob("*.py")):
            if f.name.startswith("_") or f.name == "__init__.py":
                continue
            try:
                m = importlib.import_module(f"modules.{f.stem}")
                for attr in dir(m):
                    obj = getattr(m, attr)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, Module)
                        and obj is not Module
                    ):
                        inst = obj()
                        inst.sessions = self.sessions
                        self.modules[inst.name] = inst
            except Exception as e:
                print(f"{C.R}[!] Failed to load {f.name}: {e}{C.END}")


class UI:
    commands = (
        "use", "set", "unset", "show", "options", "run", "exploit",
        "exit", "quit", "back", "help", "info", "modules", "listener",
        "menu", "home", "search", "banner", "clear", "sessions", "listeners",
    )

    def __init__(self, registry: Registry, show_banner=True):
        self.registry = registry
        self.current: Optional[Module] = None
        self.terminal = Terminal(C)
        self.show_banner = show_banner
        self._setup_completion()

    def _module_items(self):
        return sorted(self.registry.modules.items())

    def _setup_completion(self):
        if not readline:
            return

        def completer(text, state):
            line = readline.get_line_buffer().lstrip()
            command = line.split()[0].lower() if line.split() else ""
            if readline.get_begidx() == 0:
                opts = list(self.commands)
            elif command == "use":
                opts = list(self.registry.modules)
                opts += [
                    module_style(mod)["path"]
                    for _, mod in self._module_items()
                ]
                opts += [
                    str(i) for i in range(1, len(self.registry.modules) + 1)
                ]
            elif command in ("set", "unset") and self.current:
                opts = list(self.current.options)
            elif command == "show":
                opts = ["options", "modules"]
            else:
                opts = []
            matches = sorted({
                opt for opt in opts
                if opt.lower().startswith(text.lower())
            })
            return matches[state] if state < len(matches) else None

        readline.set_completer(completer)
        readline.set_completer_delims(" \t\n")
        if "libedit" in (readline.__doc__ or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    def banner(self):
        self.terminal.art("WIBEH4CK")
        self.terminal.heading("WibeH4Ck // INTERACTIVE CONSOLE")
        categories = {
            module_style(mod)["category"]
            for _, mod in self._module_items()
        }
        self.terminal.note(
            f"{len(self.registry.modules)} modules  /  "
            f"{len(categories)} categories  /  HTB + THM"
        )
        self.terminal.note("Bloody Cyan  |  QmFkLVBp")

    def menu(self):
        rows = [
            (str(i), name, module_style(mod)["category"])
            for i, (name, mod) in enumerate(self._module_items(), 1)
        ]
        self.terminal.table(
            "MODULE MENU", ("#", "Module", "Category"), rows
        )
        self.terminal.note("Select: <number> or use <module>")
        self.terminal.note(
            "help = commands  |  search <text> = filter  |  exit = quit"
        )
        print()

    def prompt(self) -> str:
        def style(code):
            if code and readline:
                return f"\001{code}\002"
            return code

        prompt = f"{style(C.BOLD)}{style(C.CY)}wibe{style(C.END)}"
        if self.current:
            path = module_style(self.current)["path"]
            prompt += f" {style(C.Y)}({path}){style(C.END)}"
        return prompt + " > "

    def run(self):
        if self.show_banner:
            self.banner()
        self.menu()
        while True:
            self.announce_sessions()
            try:
                line = input(self.prompt()).strip()
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue
            if not line:
                continue
            try:
                parts = shlex.split(line)
                self.dispatch(parts[0].lower(), parts[1:])
            except SystemExit:
                raise
            except Exception as e:
                print(f"{C.R}[!] {e}{C.END}")

    def dispatch(self, cmd: str, args: List[str]):
        if cmd in ("exit", "quit", "q"):
            raise SystemExit
        elif cmd in ("help", "?"):
            self.help()
        elif cmd == "modules":
            self.list_modules()
        elif cmd == "search":
            self.list_modules(" ".join(args))
        elif cmd == "menu":
            self.menu()
        elif cmd == "home":
            self.current = None
            self.banner()
            self.menu()
        elif cmd == "banner":
            if self.current:
                self.terminal.art(module_style(self.current)["title"])
            else:
                self.banner()
        elif cmd == "clear":
            self.terminal.clear()
            if self.current:
                self.module_info()
            else:
                self.banner()
                self.menu()
        elif cmd == "use" or (cmd.isdigit() and not args):
            self.use(args if cmd == "use" else [cmd])
        elif cmd == "set":
            self.set_opt(args)
        elif cmd == "unset":
            self.unset_opt(args)
        elif cmd == "show":
            self.show(args)
        elif cmd == "options":
            self.show(["options"])
        elif cmd in ("run", "exploit", "r", "x"):
            self.do_run()
        elif cmd == "back":
            self.current = None
            print(f"{C.Y}[*] Module unloaded{C.END}")
            self.menu()
        elif cmd == "listener":
            self.listener_cmd(args)
        elif cmd == "listeners":
            self.list_listeners()
        elif cmd == "sessions":
            self.sessions_cmd(args)
        elif cmd == "info":
            self.module_info()
        else:
            print(f"{C.R}Unknown command: {cmd} (try 'help'){C.END}")

    def help(self):
        self.terminal.table(
            "CONSOLE COMMANDS",
            ("Command", "Description"),
            [
                ("menu / home", "Show menu / return to the main screen"),
                ("modules", "List all modules and categories"),
                ("search <text>", "Filter by name, category or description"),
                (
                    "use <name|number>",
                    "Select a module; number alone works too",
                ),
                ("info", "Show the selected module and its Bloody art"),
                (
                    "show options / options",
                    "Show current values and requirements",
                ),
                ("set <OPT> <value>", "Set a module option"),
                ("unset <OPT>", "Clear a module option"),
                (
                    "run / exploit / x",
                    "Validate options and execute the module",
                ),
                ("listener <port> [host]", "Start a listener (default: 0.0.0.0)"),
                ("listeners", "List TCP listeners"),
                ("listener stop <id>", "Stop accepting new connections"),
                ("sessions", "List connections; press Enter to refresh"),
                ("sessions -i <id>", "Attach; background or Ctrl+C detaches"),
                ("sessions -k <id>", "Close a session"),
                ("back", "Unload the selected module"),
                ("banner / clear", "Print the banner / redraw the screen"),
                ("exit / quit", "Close WibeH4Ck"),
            ],
        )
        self.terminal.note(
            "Tab completes commands, module names and option names."
        )
        self.terminal.note(
            "Example: use revshell -> set LHOST 127.0.0.1 -> show options"
        )

    def list_modules(self, query=""):
        rows = []
        for i, (name, mod) in enumerate(self._module_items(), 1):
            meta = module_style(mod)
            text = (
                f"{name} {meta['category']} {meta['path']} {mod.description}"
            )
            if query.casefold() not in text.casefold():
                continue
            rows.append((str(i), name, meta["category"], mod.description))
        self.terminal.table(
            "MODULES" if not query else f"SEARCH :: {query}",
            ("#", "Module", "Category", "Description"),
            rows,
        )
        if not rows:
            self.terminal.note("No modules matched.")

    def module_info(self, with_options=False):
        if not self.current:
            print(f"{C.R}No module loaded. Use menu or use <module>.{C.END}")
            return
        meta = module_style(self.current)
        self.terminal.art(meta["title"])
        rows = [
            ("Name", self.current.name),
            ("Path", meta["path"]),
            ("Category", meta["category"]),
            ("Description", self.current.description),
        ]
        if self.current.author:
            rows.append(("Author", self.current.author))
        self.terminal.table("MODULE INFO", ("Field", "Value"), rows)
        if with_options:
            self.show(["options"])
            self.terminal.note("Set options with set OPT value, then run.")
            print()

    def use(self, args: List[str]):
        if not args:
            print(f"{C.R}Usage: use <module|number>{C.END}")
            return
        name = args[0]
        items = self._module_items()
        if name.isdigit():
            index = int(name) - 1
            if index < 0 or index >= len(items):
                print(f"{C.R}No such module number: {name}{C.END}")
                return
            name = items[index][0]
        else:
            for module_name, mod in items:
                if name == module_style(mod)["path"]:
                    name = module_name
                    break
        if name not in self.registry.modules:
            print(f"{C.R}No such module: {name}{C.END}")
            return
        self.current = self.registry.modules[name]
        self.module_info(with_options=True)

    def set_opt(self, args: List[str]):
        if not self.current:
            print(f"{C.R}Load a module first.{C.END}")
            return
        if len(args) < 2:
            print(f"{C.R}Usage: set OPT value{C.END}")
            return
        k, v = args[0].upper(), " ".join(args[1:])
        if self.current.set(k, v):
            print(f"{C.G}{k} => {self.current.get(k)}{C.END}")
        else:
            print(f"{C.R}Unknown option: {k}{C.END}")

    def unset_opt(self, args: List[str]):
        if not self.current or not args:
            return
        k = args[0].upper()
        self.current.unset(k)
        print(f"{C.Y}{k} => {self.current.get(k)!s}{C.END}")

    def show(self, args: List[str]):
        if args and args[0].lower() == "modules":
            self.list_modules()
            return
        if not args or args[0].lower() != "options":
            print(f"{C.R}Usage: show options | show modules{C.END}")
            return
        if not self.current:
            print(f"{C.R}No module loaded.{C.END}")
            return
        rows = []
        for k, v in self.current.options.items():
            value = "" if v.get("value") is None else str(v["value"])
            rows.append(
                (
                    k,
                    "yes" if v.get("required") else "no",
                    value or "<unset>",
                    v.get("description", ""),
                )
            )
        self.terminal.table(
            f"OPTIONS :: {self.current.name}",
            ("Name", "Required", "Value", "Description"),
            rows,
        )

    def do_run(self):
        if not self.current:
            print(f"{C.R}No module loaded.{C.END}")
            return
        errs = self.current.validate()
        if errs:
            print(f"{C.R}Validation errors:{C.END}")
            for e in errs:
                print(f" {C.R}- {e}{C.END}")
            return
        print(f"{C.Y}[*] Running '{self.current.name}'...{C.END}\n")
        try:
            self.current.run()
        except NotImplementedError:
            print(
                f"{C.R}Module '{self.current.name}' "
                f"has no run() implemented.{C.END}"
            )
        except KeyboardInterrupt:
            print(f"\n{C.Y}[*] Aborted.{C.END}")
        except Exception as e:
            print(f"{C.R}[!] Exploit error: {type(e).__name__}: {e}{C.END}")

    def announce_sessions(self):
        while True:
            try:
                message = self.registry.sessions.notices.get_nowait()
            except queue.Empty:
                return
            print(f"{C.G}[+] {message}{C.END}")

    def listener_cmd(self, args: List[str]):
        manager = self.registry.sessions
        if len(args) == 2 and args[0] == "stop":
            manager.stop_listener(int(args[1]))
            print(f"{C.Y}[*] Listener {args[1]} stopped.{C.END}")
            return
        if not 1 <= len(args) <= 2:
            print(f"{C.R}Usage: listener <port> [host] | listener stop <id>{C.END}")
            return
        host = args[1] if len(args) == 2 else "0.0.0.0"
        err = validate_opt("LPORT", args[0]) or validate_opt("LHOST", host)
        if err:
            raise ValueError(err)
        listener = manager.listen(host, int(args[0]))
        print(f"{C.G}[+] Listener {listener.id} on {host}:{listener.port}{C.END}")
        self.terminal.note("Use sessions to view connections; Enter refreshes notices.")

    def list_listeners(self):
        rows = [
            (item.id, f"{item.host}:{item.port}",
             "stopped" if item.stopped.is_set() else "listening")
            for item in self.registry.sessions.listeners()
        ]
        self.terminal.table("LISTENERS", ("ID", "Address", "State"), rows)

    def sessions_cmd(self, args):
        manager = self.registry.sessions
        if not args:
            rows = [
                (item.id, item.peer, "closed" if item.closed.is_set() else "open")
                for item in manager.sessions()
            ]
            self.terminal.table("SESSIONS", ("ID", "Peer", "State"), rows)
            self.terminal.note("sessions -i <id> = attach | sessions -k <id> = close")
            return
        if len(args) != 2 or args[0] not in ("-i", "-k"):
            raise ValueError("Usage: sessions [-i <id> | -k <id>]")
        session = manager.get(int(args[1]))
        if args[0] == "-k":
            session.close()
        else:
            session.interact()


_ANSI_VALUES = {
    name: getattr(C, name)
    for name in ("R", "G", "Y", "B", "M", "CY", "W", "DIM", "BOLD", "END")
}


def configure_colors(no_color=False):
    enabled = (
        not no_color
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM") != "dumb"
        and sys.stdout.isatty()
    )
    for name, value in _ANSI_VALUES.items():
        setattr(C, name, value if enabled else "")


def main():
    p = argparse.ArgumentParser(
        prog="rce.py",
        description="WibeH4Ck - modular HTB/THM terminal console",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 rce.py                   open the console\n"
            "  python3 rce.py -l                list modules\n"
            "  python3 rce.py --no-color        plain terminal output\n"
            "\nInside the console: menu, help, use <module>, show options."
        ),
    )
    p.add_argument("-m", "--module", help="run module directly")
    p.add_argument(
        "-o", "--option", action="append", default=[], metavar="K=V"
    )
    p.add_argument("-l", "--list", action="store_true", help="list modules")
    p.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors"
    )
    p.add_argument(
        "--no-banner", action="store_true", help="hide the startup art"
    )
    a = p.parse_args()
    configure_colors(a.no_color)
    reg = Registry()

    try:
        if a.list:
            for n, m in sorted(reg.modules.items()):
                print(f"{n:<22} {m.description}")
            return

        if a.module:
            if a.module not in reg.modules:
                raise ValueError(f"No such module: {a.module}")
            module = reg.modules[a.module]
            for kv in a.option:
                if "=" not in kv:
                    raise ValueError(f"Invalid option {kv!r}; expected K=V")
                key, value = kv.split("=", 1)
                if not module.set(key.upper(), value):
                    raise ValueError(f"Unknown option: {key}")
            errs = module.validate()
            if errs:
                raise ValueError("Validation errors: " + ", ".join(errs))
            module.run()
            # A detached connection from direct mode still needs a console owner.
            if any(not session.closed.is_set() for session in reg.sessions.sessions()):
                ui = UI(reg, show_banner=False)
                ui.current = module
                ui.run()
            return

        if a.option:
            raise ValueError("-o requires -m <module>")
        UI(reg, show_banner=not a.no_banner).run()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[*] Aborted.{C.END}")
        raise SystemExit(130)
    except Exception as exc:
        print(f"{C.R}[!] {exc}{C.END}", file=sys.stderr)
        raise SystemExit(1)
    finally:
        reg.sessions.close()
