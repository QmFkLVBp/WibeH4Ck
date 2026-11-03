#!/usr/bin/env python3
"""framework.py — минималистичное ядро RCE-фреймворка для HTB/THM."""
import sys, importlib, threading, socket, argparse, shlex, select, shutil
import re
from pathlib import Path
from typing import Dict, Any, Optional, List

try:
import readline
except ImportError:
readline = None

class C:
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; CY="\033[96m"; W="\033[97m"; DIM="\033[2m"
BOLD="\033[1m"; END="\033[0m"

def require(*bins: str) -> List[str]:
return [b for b in bins if not shutil.which(b)]

def validate_opt(name: str, value: Any) -> Optional[str]:
"""Простая валидация формата. Возвращает текст ошибки или None."""
if value is None:
return None
v = str(value)
if name in ("LHOST", "TARGET") and "://" not in v:
if not re.match(r"^[a-zA-Z0-9._-]+$", v):
return f"{name}: похоже на некорректный хост/IP ({v})"
if name in ("LPORT", "RPORT", "CB_PORT", "HTTP_PORT", "WEBPORT"):
try:
p = int(v)
if not (1 <= p <= 65535):
return f"{name}: порт вне диапазона 1..65535 ({p})"
except ValueError:
return f"{name}: должен быть числом ({v})"
return None

def interactive_shell(sock: socket.socket, banner: str = "[+] Shell opened"):
print(f"\n{C.G}{banner}{C.END}")
print(f"{C.DIM}Type 'background' to detach.{C.END}\n")
sock.settimeout(0.1)
try:
while True:
try:
r, _, _ = select.select([sock, sys.stdin], [], [], 0.5)
except (OSError, ValueError):
break
if sock in r:
try:
data = sock.recv(4096)
except (socket.timeout, ConnectionResetError):
continue
if not data:
print(f"\n{C.Y}[*] Connection closed{C.END}")
break
sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
if sys.stdin in r:
try:
line = sys.stdin.readline()
except KeyboardInterrupt:
break
if not line or line.strip().lower() in ("background", "bg"):
break
try:
sock.sendall(line.encode())
except (BrokenPipeError, ConnectionResetError):
break
except KeyboardInterrupt:
print()
finally:
try: sock.close()
except Exception: pass

class Module:
name = "base"
description = ""
author = ""
options: Dict[str, Dict[str, Any]] = {}

def set(self, k: str, v: Any) -> bool:
if k in self.options:
self.options[k]["value"] = v
return True
return False

def get(self, k: str) -> Any:
return self.options[k]["value"]

def validate(self) -> List[str]:
errs = []
for k, v in self.options.items():
if v.get("required") and not v.get("value"):
errs.append(f"missing {k}")
continue
e = validate_opt(k, v.get("value"))
if e:
errs.append(e)
return errs

def run(self) -> None:
raise NotImplementedError

def info(self) -> None:
print(f"\n{C.BOLD}{C.CY}Module:{C.END} {self.name}")
print(f"{C.BOLD}Description:{C.END} {self.description}")
if self.author:
print(f"{C.BOLD}Author:{C.END} {self.author}")

class Listener:
def init(self, host: str = "0.0.0.0", port: int = 4444):
self.host, self.port = host, port

def start(self) -> None:
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((self.host, self.port)); s.listen(1)
print(f"{C.G}[+] Listener on {self.host}:{self.port}{C.END}")

def serve():
try:
cl, ad = s.accept()
print(f"\n{C.G}[+] Connection from {ad[0]}:{ad[1]}{C.END}")
interactive_shell(cl)
except Exception as e:
print(f"{C.R}[!] Listener error: {e}{C.END}")
finally:
s.close()

threading.Thread(target=serve, daemon=True).start()

class Registry:
def init(self, modules_dir: Optional[Path] = None):
self.modules_dir = modules_dir or (Path(file).parent / "modules")
self.modules: Dict[str, Module] = {}
self._load()

def load(self) -> None:
if not self.modules_dir.exists():
print(f"{C.R}[!] modules/ not found at {self.modules_dir}{C.END}")
return
parent = self.modules_dir.parent
if str(parent) not in sys.path:
sys.path.insert(0, str(parent))
for f in sorted(self.modules_dir.glob("*.py")):
if f.name.startswith("") or f.name == "init.py":
continue
try:
m = importlib.import_module(f"modules.{f.stem}")
for attr in dir(m):
obj = getattr(m, attr)
if (isinstance(obj, type) and issubclass(obj, Module)
and obj is not Module):
inst = obj()
self.modules[inst.name] = inst
except Exception as e:
print(f"{C.R}[!] Failed to load {f.name}: {e}{C.END}")

class UI:
def init(self, registry: Registry):
self.registry = registry
self.current: Optional[Module] = None
self._setup_completion()

def _setup_completion(self):
if not readline: return
def completer(text, state):
opts = ["use","set","unset","show","run","exploit","exit","quit",
"back","help","info","modules","listener"]
if self.current:
opts += list(self.current.options.keys())
matches = [o for o in opts if o.lower().startswith(text.lower())]
return matches[state] if state < len(matches) else None
readline.set_completer(completer)
readline.parse_and_bind("tab: complete")

def banner(self):
print(f"""{C.CY}{C.BOLD}

| _ \/ | | / _| | | | | _|
| / (| | \ \ | | | || | | |
||\\|| |/ || \/ ||
{C.END}{C.DIM} mini RCE framework — HTB/THM friendly{C.END}
""")

def prompt(self) -> str:
tag = f"{C.Y}({self.current.name}){C.END}" if self.current else f"{C.DIM}(no module){C.END}"
return f"{C.G}rce{C.END} {tag} > "

def run(self):
self.banner()
print(f"{C.DIM}Type 'help' or 'modules'. Tab-completion works.{C.END}\n")
while True:
try:
line = input(self.prompt()).strip()
except (EOFError, KeyboardInterrupt):
print(); break
if not line: continue
parts = shlex.split(line)
try:
self.dispatch(parts[0].lower(), parts[1:])
except SystemExit:
raise
except Exception as e:
print(f"{C.R}[!] {e}{C.END}")

def dispatch(self, cmd: str, args: List[str]):
if cmd in ("exit","quit","q"): raise SystemExit
elif cmd in ("help","?"): self.help()
elif cmd == "modules": self.list_modules()
elif cmd == "use": self.use(args)
elif cmd == "set": self.set_opt(args)
elif cmd == "unset": self.unset_opt(args)
elif cmd == "show": self.show(args)
elif cmd in ("run","exploit","r","x"): self.do_run()
elif cmd == "back":
self.current = None
print(f"{C.Y}[*] Module unloaded{C.END}")
elif cmd == "listener": self.listener_cmd(args)
elif cmd == "info":
if self.current: self.current.info()
else: print(f"{C.R}No module loaded.{C.END}")
else:
print(f"{C.R}Unknown command: {cmd} (try 'help'){C.END}")

def help(self):
print(f"""
{C.BOLD}Commands:{C.END}
modules list available modules
use <name> select module
info show current module info
show options show options
set <OPT> <value> set option
unset <OPT> clear option
run | exploit | x execute module
listener <port> background reverse-shell listener
back unload module
exit | quit leave
""")

def list_modules(self):
print(f"\n{C.BOLD}Modules:{C.END}\n")
if not self.registry.modules:
print(f" {C.DIM}(none — drop *.py files into modules/){C.END}")
for name, mod in sorted(self.registry.modules.items()):
print(f" {C.CY}{name:<22}{C.END} {mod.description}")
print()

def use(self, args: List[str]):
if not args:
print(f"{C.R}Usage: use <module>{C.END}"); return
if args[0] not in self.registry.modules:
print(f"{C.R}No such module: {args[0]}{C.END}"); return
self.current = self.registry.modules[args[0]]
self.current.info()
print(f"\n{C.DIM}Set options with 'set OPT value', then 'run'.{C.END}")

def set_opt(self, args: List[str]):
if not self.current:
print(f"{C.R}Load a module first.{C.END}"); return
if len(args) < 2:
print(f"{C.R}Usage: set OPT value{C.END}"); return
k, v = args[0].upper(), " ".join(args[1:])
if self.current.set(k, v):
err = validate_opt(k, v)
if err:
print(f"{C.Y}{k} => {v} (warning: {err}){C.END}")
else:
print(f"{C.G}{k} => {v}{C.END}")
else:
print(f"{C.R}Unknown option: {k}{C.END}")

def unset_opt(self, args: List[str]):
if not self.current or not args: return
k = args[0].upper()
if k in self.current.options:
self.current.options[k]["value"] = None
print(f"{C.Y}{k} cleared{C.END}")

def show(self, args: List[str]):
if not args or args[0].lower() != "options":
print(f"{C.R}Usage: show options{C.END}"); return
if not self.current:
print(f"{C.R}No module loaded.{C.END}"); return
print(f"\n{C.BOLD}Options for {self.current.name}:{C.END}\n")
print(f" {'Name':<14} {'Req':<4} {'Value':<28} Description")
print(f" {'-'14} {'-'4} {'-'28} {'-'30}")
for k, v in self.current.options.items():
req = "*" if v.get("required") else ""
val = str(v.get("value") if v.get("value") is not None else "")
print(f" {C.CY}{k:<14}{C.END} {req:<4} {val:<28} {v.get('description','')}")
print()

def do_run(self):
if not self.current:
print(f"{C.R}No module loaded.{C.END}"); return
errs = self.current.validate()
if errs:
print(f"{C.R}Validation errors:{C.END}")
for e in errs: print(f" {C.R}- {e}{C.END}")
return
print(f"{C.Y}[] Running '{self.current.name}'...{C.END}\n")
try:
self.current.run()
except NotImplementedError:
print(f"{C.R}Module '{self.current.name}' has no run() implemented.{C.END}")
except KeyboardInterrupt:
print(f"\n{C.Y}[] Aborted.{C.END}")
except Exception as e:
print(f"{C.R}[!] Exploit error: {type(e).name}: {e}{C.END}")

def listener_cmd(self, args: List[str]):
if not args:
print(f"{C.R}Usage: listener <port>{C.END}"); return
try: port = int(args[0])
except ValueError:
print(f"{C.R}Invalid port{C.END}"); return
Listener(port=port).start()

def main():
p = argparse.ArgumentParser(description="mini RCE framework")
p.add_argument("-m","--module", help="run module directly")
p.add_argument("-o","--option", action="append", default=[], metavar="K=V")
p.add_argument("-l","--list", action="store_true")
a = p.parse_args()

reg = Registry()

if a.list:
for n, m in sorted(reg.modules.items()):
print(f"{n:<22} {m.description}")
return

if a.module:
if a.module not in reg.modules:
print(f"{C.R}No such module: {a.module}{C.END}"); sys.exit(1)
m = reg.modules[a.module]
for kv in a.option:
if "=" in kv:
k, v = kv.split("=", 1); m.set(k.upper(), v)
errs = m.validate()
if errs:
print(f"{C.R}Validation errors: {', '.join(errs)}{C.END}")
sys.exit(1)
m.run(); return

UI(reg).run()
