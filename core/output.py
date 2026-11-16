# language: python, file: core/output.py
import os, sys, re, datetime

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"

_REPORT = []

def _enable_ansi():
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass

_enable_ansi()

_ANSI_RE = re.compile(r"\033\[\d+m")

def _emit(msg, color=""):
    sys.stdout.write(f"{color}{msg}{RESET}\n")
    sys.stdout.flush()
    _REPORT.append(_ANSI_RE.sub("", msg))

def phase(name):   _emit(f"\n=== {name} ===", MAGENTA + BOLD)
def info(msg):     _emit(msg, CYAN)
def ok(msg):       _emit(msg, GREEN)
def warn(msg):     _emit(msg, YELLOW)
def fail(msg):     _emit(msg, RED)
def detail(msg):   _emit(f"  {msg}", DIM)
def kv(k, v):      _emit(f"  {k:<12}{v}", WHITE)

# back-compat
p_print = info

def clear_console():
    os.system("cls" if os.name == "nt" else "clear")

def reset_report():
    _REPORT.clear()

def report_path(target):
    host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    host = re.sub(r"[^A-Za-z0-9._-]", "_", host) or "target"
    n = 1
    while os.path.exists(f"report_{host}_{n}.txt"):
        n += 1
    return f"report_{host}_{n}.txt"

def write_report(target, state):
    path = report_path(target)
    with open(path, "w", encoding="utf-8") as f:
        f.write("WibeH4Ck report\n")
        f.write("=" * 60 + "\n")
        f.write(f"target : {target}\n")
        f.write(f"date   : {datetime.datetime.utcnow().isoformat()}Z\n")
        f.write(f"host   : {os.environ.get('COMPUTERNAME') or os.uname().nodename if hasattr(os,'uname') else '?'}\n")
        if state:
            fp = state.get("fingerprint") or {}
            f.write(f"wp     : {fp.get('wp_version')}\n")
            f.write(f"waf    : {fp.get('waf')}\n")
            f.write(f"phases : {','.join(state.get('phases',[])) or 'none'}\n")
        f.write("=" * 60 + "\n\n")
        for line in _REPORT:
            f.write(line + "\n")
    return path

def export_json(path, data):
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
