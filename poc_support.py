"""Checked subprocesses and isolated Python environments for external PoCs."""
import hashlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def run_checked(command, cwd=None, timeout=None, capture_output=False):
    try:
        result = subprocess.run(
            [str(part) for part in command], cwd=cwd, timeout=timeout,
            capture_output=capture_output, text=True, check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Executable not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {command[0]}") from exc
    if result.returncode:
        detail = (result.stderr or "").strip() if capture_output else ""
        raise RuntimeError(
            f"{command[0]} exited with code {result.returncode}"
            + (f": {detail[-2000:]}" if detail else "")
        )
    return result


def ensure_repo(repo, work, entrypoint):
    work = Path(work)
    if (work / entrypoint).is_file():
        return
    if work.exists():
        raise RuntimeError(
            f"Incomplete PoC directory {work}: {entrypoint} is missing. "
            "Move it aside and retry."
        )
    work.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Cloning {repo}")
    with tempfile.TemporaryDirectory(dir=work.parent, prefix=".clone-") as tmp:
        checkout = Path(tmp) / "checkout"
        run_checked(
            ["git", "clone", "--depth", "1", repo, checkout], timeout=180
        )
        if not (checkout / entrypoint).is_file():
            raise RuntimeError(f"Upstream PoC has no {entrypoint}")
        checkout.rename(work)


def python_environment(work):
    work = Path(work)
    env = work / ".venv"
    python = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    created = not python.is_file()
    if created:
        run_checked([sys.executable, "-m", "venv", env], timeout=120)
    req = work / "requirements.txt"
    if req.is_file():
        stamp = env / ".requirements.sha256"
        digest = hashlib.sha256(req.read_bytes()).hexdigest()
        previous = stamp.read_text().strip() if stamp.exists() else None
        if created or previous != digest:
            print("[*] Installing PoC requirements in its .venv")
            run_checked(
                [python, "-m", "pip", "install", "-r", req.resolve()],
                cwd=work, timeout=300,
            )
            stamp.write_text(digest + "\n")
    # Resolving the symlink would bypass the venv and run the system interpreter.
    return str(python.absolute())


def stop_process(process):
    """Reap the parent and terminate its own group, including Java children."""
    def send(sig):
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            elif process.poll() is None:
                process.terminate() if sig == signal.SIGTERM else process.kill()
        except ProcessLookupError:
            pass

    send(signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        send(signal.SIGKILL)
        process.wait(timeout=3)
    else:
        # The parent may have exited before a child in its process group.
        if os.name == "posix":
            send(signal.SIGKILL)


def check_free_ports(ports):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("0.0.0.0", port))
            except OSError as exc:
                raise RuntimeError(f"Required local port {port} is busy") from exc


def wait_for_ports(process, ports, timeout=15):
    pending = set(ports)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"PoC exited during startup: {process.returncode}")
        for port in tuple(pending):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    pending.remove(port)
            except OSError:
                pass
        if pending:
            time.sleep(0.1)
    if pending:
        raise RuntimeError(f"PoC did not open local ports: {sorted(pending)}")
