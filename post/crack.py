# language: python, file: post/crack.py
import os, shutil, subprocess, tempfile

def crack_hashes(hashes, wordlist, mode=400, timeout=1800):
    if not hashes:
        return {}
    if not os.path.isfile(wordlist):
        return {"__error__": f"wordlist missing: {wordlist}"}
    if not shutil.which("hashcat"):
        return {"__error__": "hashcat not on PATH"}

    fd, hashfile = tempfile.mkstemp(suffix=".txt", text=True)
    user_by_hash = {}
    try:
        with os.fdopen(fd, "w") as f:
            for u, h in hashes.items():
                h = h.strip()
                f.write(h + "\n")
                user_by_hash[h] = u

        run = subprocess.run(
            ["hashcat", "-m", str(mode), "-a", "0", hashfile, wordlist,
             "--potfile-disable", "--quiet", "--force",
             "--status", "--status-timer=15"],
            capture_output=True, text=True, timeout=timeout)

        show = subprocess.run(
            ["hashcat", "-m", str(mode), hashfile,
             "--potfile-disable", "--show", "--quiet", "--force"],
            capture_output=True, text=True)

        cracked = {}
        for line in show.stdout.splitlines():
            if ":" not in line:
                continue
            h, pw = line.strip().split(":", 1)
            if h in user_by_hash:
                cracked[user_by_hash[h]] = pw
        return cracked
    except subprocess.TimeoutExpired:
        return {"__error__": f"hashcat timeout {timeout}s"}
    finally:
        try: os.unlink(hashfile)
        except OSError: pass
