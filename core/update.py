# language: python, file: core/update.py
import os, shutil, subprocess, urllib.request

REPO   = "QmFkLVBp/WibeH4Ck"
BRANCH = "main"
RAW    = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}"

WORDFENCE_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
WORDLIST_URL  = ("https://raw.githubusercontent.com/danielmiessler/SecLists/"
                 "master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt")

FILES = [
    "wibeh4ck.py",
    "core/__init__.py", "core/http.py", "core/output.py", "core/waf.py", "core/update.py",
    "recon/__init__.py", "recon/fingerprint.py",
    "exploit/__init__.py", "exploit/template_sqli.py",
    "post/__init__.py", "post/crack.py", "post/shell.py", "post/persist.py",
]

SAMPLE_DB = {
    "CVE-2024-27956": {
        "cve": "CVE-2024-27956",
        "title": "WP Automatic < 3.92.1 — Unauthenticated SQL Injection",
        "cvss": {"score": 9.8},
        "cwe": {"name": "SQL Injection"},
        "software": [{"type": "plugin", "slug": "wp-automatic",
                      "affected_versions": [{"from": "0", "to": "3.92.1", "to_inc": False}]}]
    },
    "CVE-2023-2982": {
        "cve": "CVE-2023-2982",
        "title": "WordPress Social Login < 2.3.3 — Auth Bypass",
        "cvss": {"score": 9.8},
        "cwe": {"name": "Authentication Bypass"},
        "software": [{"type": "plugin", "slug": "wordpress-social-login",
                      "affected_versions": [{"from": "0", "to": "2.3.3", "to_inc": False}]}]
    },
    "CVE-2023-5360": {
        "cve": "CVE-2023-5360",
        "title": "Royal Elementor Addons < 1.3.79 — Arbitrary File Upload",
        "cvss": {"score": 9.8},
        "cwe": {"name": "Unrestricted Upload"},
        "software": [{"type": "plugin", "slug": "royal-elementor-addons",
                      "affected_versions": [{"from": "0", "to": "1.3.79", "to_inc": False}]}]
    },
}

def _download(url, dest, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": "WibeH4Ck"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)

def _ensure(path, url, timeout=90):
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        return False
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    _download(url, tmp, timeout=timeout)
    os.replace(tmp, path)
    return True

def update_code(root):
    if not (shutil.which("git") and os.path.isdir(os.path.join(root, ".git"))):
        return None, "no git repo — file sync only"
    r = subprocess.run(["git", "-C", root, "pull", "--ff-only"],
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip() or "(no output)"

def update_files(root):
    changed, same, errors = [], [], []
    for rel in FILES:
        path = os.path.join(root, rel)
        tmp = path + ".new"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        try:
            _download(f"{RAW}/{rel}", tmp, timeout=20)
        except Exception as e:
            errors.append((rel, f"download: {e}"))
            if os.path.exists(tmp): os.remove(tmp)
            continue
        if os.path.isfile(path):
            try:
                with open(path, "rb") as a, open(tmp, "rb") as b:
                    if a.read() == b.read():
                        os.remove(tmp); same.append(rel); continue
            except OSError:
                pass
        try:
            os.replace(tmp, path)
            changed.append(rel)
        except OSError as e:
            os.replace(tmp, path + ".new")
            errors.append((rel, f"locked (restart): {e}"))
    return changed, same, errors

def ensure_data(root, log_detail, log_ok, log_warn):
    # wordfence feed — big, may fail, falls back to sample
    wf = os.path.join(root, "data", "wordfence.json")
    if not (os.path.isfile(wf) and os.path.getsize(wf) > 0):
        log_detail("wordfence feed (may take minutes)...")
        try:
            _ensure(wf, WORDFENCE_URL, timeout=600)
            log_ok("wordfence feed downloaded")
        except Exception as e:
            log_warn(f"wordfence feed failed: {e}")
            import json
            os.makedirs(os.path.dirname(wf), exist_ok=True)
            with open(wf, "w") as f:
                json.dump(SAMPLE_DB, f, indent=2)
            log_warn(f"fallback: wrote {len(SAMPLE_DB)}-CVE sample to data/wordfence.json")

    # wordlist fallback
    wl = os.path.join(root, "wordlists", "wordlist.txt")
    if not (os.path.isfile(wl) and os.path.getsize(wl) > 0):
        log_detail("wordlist (100k common passwords)...")
        try:
            _ensure(wl, WORDLIST_URL)
            log_ok("wordlists/wordlist.txt downloaded")
        except Exception as e:
            log_warn(f"wordlist failed: {e}")

    # __init__ markers
    for pkg in ("core", "recon", "exploit", "post"):
        init = os.path.join(root, pkg, "__init__.py")
        if not os.path.isfile(init):
            os.makedirs(os.path.dirname(init), exist_ok=True)
            open(init, "w").close()
