"""Offline Bloody banners and terminal layout for the WibeH4Ck console."""
import json
import shutil
import sys
import textwrap
from itertools import groupby, zip_longest
from pathlib import Path


MODULE_STYLE = {
    "revshell": {
        "title": "REVSHELL",
        "category": "PAYLOAD / SHELL",
        "path": "payload/revshell",
    },
    "log4shell": {
        "title": "LOG4SHELL",
        "category": "JAVA / LOG4J",
        "path": "exploit/java/log4shell",
    },
    "cve_2024_4577": {
        "title": "PHP CGI",
        "category": "PHP / WINDOWS",
        "path": "exploit/php/cve_2024_4577",
    },
    "cve_2019_11043": {
        "title": "PHP FPM",
        "category": "PHP / FPM",
        "path": "exploit/php/cve_2019_11043",
    },
}

SHADES = {
    "c": "\033[0;36m",
    "h": "\033[0;97;46m",
    "w": "\033[0;97m",
    "d": "\033[0;37m",
    "b": "\033[0;36;46m",
}


def module_style(module):
    return MODULE_STYLE.get(
        module.name,
        {
            "title": module.name.upper(),
            "category": "CUSTOM",
            "path": f"modules/{module.name}",
        },
    )


class Terminal:
    def __init__(self, colors):
        self.colors = colors
        try:
            font_path = Path(__file__).parent / "assets" / "bloody.json"
            self.font = json.loads(font_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.font = None

    @property
    def width(self):
        return max(20, min(120, shutil.get_terminal_size((100, 24)).columns))

    def heading(self, title):
        c = self.colors
        available = max(1, self.width - 4)
        print()
        for line in textwrap.wrap(title, available):
            print(f"  {c.BOLD}{c.CY}{line}{c.END}")
        print(f"  {c.DIM}{'-' * available}{c.END}")

    def art(self, title):
        c = self.colors
        glyphs = self.font["glyphs"] if self.font else {}
        title = title.upper()
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        try:
            "█▓▒░".encode(encoding)
            supported = all(char in glyphs for char in title)
        except (LookupError, UnicodeEncodeError):
            supported = False
        art_width = (
            sum(len(glyphs[char][0][0]) for char in title)
            if supported else self.width
        )
        print()
        if not supported or art_width > self.width - 4:
            for line in textwrap.wrap(title, max(1, self.width - 4)):
                print(f"  {c.BOLD}{c.CY}{line}{c.END}")
            return
        padding = " " * max(2, (self.width - art_width) // 2)
        rows = []
        for row in range(self.font["height"]):
            text = "".join(glyphs[char][row][0] for char in title)
            shades = "".join(glyphs[char][row][1] for char in title)
            rows.append((text, shades))
        while rows and not rows[-1][0].strip():
            rows.pop()
        for text, shades in rows:
            if not c.END:
                print(padding + text.rstrip())
                continue
            colored = []
            for shade, cells in groupby(
                zip(text, shades), key=lambda cell: cell[1]
            ):
                colored.append(SHADES[shade])
                colored.append("".join(char for char, _ in cells))
            print(padding + "".join(colored) + c.END)

    def note(self, text):
        c = self.colors
        for line in textwrap.wrap(text, max(1, self.width - 4)):
            print(f"  {c.DIM}{line}{c.END}")

    def table(self, title, headers, rows):
        c = self.colors
        rows = [tuple(str(cell) for cell in row) for row in rows]
        columns = (
            list(zip(headers, *rows)) if rows else [(h,) for h in headers]
        )
        widths = [max(len(cell) for cell in col) for col in columns]
        available = max(len(headers), self.width - 4 - 2 * (len(headers) - 1))
        while sum(widths) > available:
            largest = max(range(len(widths)), key=widths.__getitem__)
            widths[largest] -= 1
        self.heading(title)
        header = "  ".join(
            textwrap.shorten(str(cell), width=width, placeholder=".")
            .ljust(width)
            for cell, width in zip(headers, widths)
        )
        print(f"  {c.BOLD}{header}{c.END}")
        print(
            f"  {c.DIM}"
            + "  ".join("-" * width for width in widths)
            + c.END
        )
        for row in rows:
            wrapped = [
                textwrap.wrap(
                    cell,
                    width,
                    replace_whitespace=False,
                    drop_whitespace=True,
                ) or [""]
                for cell, width in zip(row, widths)
            ]
            for parts in zip_longest(*wrapped, fillvalue=""):
                print(
                    "  "
                    + "  ".join(
                        part.ljust(width)
                        for part, width in zip(parts, widths)
                    ).rstrip()
                )
        print()

    def clear(self):
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="", flush=True)
