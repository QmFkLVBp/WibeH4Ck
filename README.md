# wibeh4ck

WordPress chain for CTF/HTB: recon → vuln match → auto-exploit → hashcat → admin login → plugin webshell.

## Setup
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    touch core/__init__.py recon/__init__.py exploit/__init__.py \
          exploit/modules/__init__.py post/__init__.py
    # For real vulnerabilities, fetch the live feed:
    curl -s https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production \
      -o data/wordfence.json
    # Then edit DEFAULT_DB in wibeh4ck.py to "data/wordfence.json"
    # Drop rockyou.txt into wordlists/

## Run
    python3 wibeh4ck.py -t https://target.htb
    python3 wibeh4ck.py -t https://target.htb --json results.json
    python3 wibeh4ck.py -t https://target.htb --wordlist ~/SecLists/Passwords/rockyou.txt
    python3 wibeh4ck.py -t https://target.htb --proxy http://127.0.0.1:8080

## Adding an exploit
1. Copy `exploit/modules/template_sqli.py` to `cve_<year>_<num>_<slug>.py`
2. Set `PLUGIN` to the vulnerable slug from recon
3. Implement `check()` (usually 1 line) and `exploit()`
4. Return a dict with `success: True` and either:
   - `type: "sqli"`, `users: [{login, hash}]` — pipeline cracks + logs in automatically
   - `type: "shell"`, `url`, `password` — pipeline skips straight to webshell stage
5. Reload — the loader picks it up by filename, no registry edit.

## Why faster than Metasploit here
- Single Python process, no session/RPC overhead
- Offline vulnerability DB — zero API roundtrips per scan
- Exploit modules are one file each, no base-class ceremony
- Webshell is a real WP plugin zip, deployed in 3 requests (upload + activate + probe)
- CVSS-ordered single-pass — stops the moment it lands a shell

## Not for
Anything you don't own or have written permission to test. HTB/CTF boxes and your own labs only.
