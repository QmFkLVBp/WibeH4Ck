"""ANSI colors, no dependencies. Auto-off on pipes, override with --color/--no-color."""
import os
import sys

_ENABLED = None


def _auto():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def enable(force=None):
    global _ENABLED
    _ENABLED = _auto() if force is None else bool(force)


enable()


def _c(text, code):
    if not _ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t):    return _c(t, "1")
def dim(t):     return _c(t, "2")
def red(t):     return _c(t, "31")
def green(t):   return _c(t, "32")
def yellow(t):  return _c(t, "33")
def blue(t):    return _c(t, "34")
def magenta(t): return _c(t, "35")
def cyan(t):    return _c(t, "36")

# semantic aliases
def ok(t):     return green(t)
def fail(t):   return red(t)
def warn(t):   return yellow(t)
def info(t):   return cyan(t)
def muted(t):  return dim(t)


def cvss_color(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return lambda t: t
    if s >= 9.0:
        return lambda t: _c(t, "1;91")   # bold bright red
    if s >= 7.0:
        return lambda t: _c(t, "91")     # bright red
    if s >= 4.0:
        return lambda t: _c(t, "33")     # yellow
    return lambda t: _c(t, "2")          # dim
