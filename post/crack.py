import os, shutil, subprocess, tempfile


def crack_hashes(hashes, wordlist_path):
    if not shutil.which("hashcat"):
        return {"error": "hashcat not on PATH — install: apt install hashcat",
                "cracked": {}}
    if not os.path.isfile(wordlist_path):
        return {"error": f"wordlist missing: {wordlist_path}", "cracked": {}}

    fd, hash_file = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(hashes))
        proc = subprocess.run(
            ["hashcat", "-m", "400", "-a", "0", hash_file, wordlist_path,
             "--quiet", "--potfile-disable", "--force"],
            capture_output=True, text=True, timeout=900,
        )
        cracked = {}
        for line in proc.stdout.splitlines():
            if ":" in line:
                h, p = line.rsplit(":", 1)
                cracked[h] = p
        return {"cracked": cracked, "raw": proc.stdout[-2000:]}
    except subprocess.TimeoutExpired:
        return {"error": "hashcat timed out", "cracked": {}}
    finally:
        os.unlink(hash_file)
