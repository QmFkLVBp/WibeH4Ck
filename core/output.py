import json
import time
from core import colors

BANNER = r"""

 █▀   █░  ██▓  ▄▄▄▄    ▓ ▄▄██   ▄█▒ ██   ▄█▄  ▄    ██ ▄█▀
▓██▓█▒█░ ▓▐█▒ ▓█▄ ██▄  ▓█   ▀  ▓██░ █▄▒ ▓ █▀ ▀█    ██▄█▒ 
▒██▒█░█  ▒ █▒ ▒██▒ ▄██ ▒█ █    ▒███▀██░ ▒▓█    ▄  ▓███▄░ 
░▒█░█ █  ░▐ ░ ▒▄ ░█▀   ▒▓█  ▄  ░▓█ ▓██  ▒▒▒▄ ▄  ▒ ▓██ █▄ 
░░██▒██▓ ░▐█░ ░▓█   █▓ ░▒████▒ ░▓█▒▓ ▄▓ ▒ ▒   ▀ ░ ▒▄█▓ █▄
 ░ ▓░▒ ▒ ░▓   ░▒▒███▀▒ ░░ ▒░ ░  ▒ ░▓▒░▒ ░ ░▒ ▓  ░ ▒ ▒▒ ▓▒
   ▒ ░ ░  ▒ ░ ▒░▒   ░   ░ ░  ░  ▒ ░▒░ ░   ░  ▒    ░ ░▒ ▒░
   ░   ░  ▒ ░  ░    ░     ░     ░  ░░ ░ ░         ░ ░░ ░ 
     ░    ░    ░          ░  ░  ░  ░  ░ ░ ░       ░  ░   
                    ░                   ░                

"""


def banner():
    print(colors.cyan(BANNER))
    print(colors.muted("  wibeh4ck — WordPress chain for CTF\n"))


# ─────────────────────────── recon ───────────────────────────

def print_recon(r, matches=None):
    matches = matches or []
    print(colors.bold("  target:      ") + str(r.get("target")))
    print(colors.bold("  wp version:  ") + colors.info(str(r.get("wp_version") or "?")))
    print(colors.bold("  waf:         ") + colors.info(str(r.get("waf") or "none detected")))
    users = ", ".join(u.get("slug", "?") for u in r.get("users") or []) or "-"
    print(colors.bold("  users:       ") + colors.info(users))

    plugins = r.get("plugins") or []
    if plugins:
        print(colors.bold("  plugins:"))
        for p in plugins:
            slug = p.get("slug", "?")
            ver = p.get("version") or "?"
            n = sum(1 for m in matches if m.get("plugin") == slug)
            if n:
                sym, fn = "✘", colors.fail
            elif "." not in str(ver):
                sym, fn = "⚠", colors.warn
            else:
                sym, fn = "✔", colors.ok
            print(f"    {fn(sym)} {slug:<42} {str(ver):<12}")
    print()


# ─────────────────────────── matches ───────────────────────────

def print_matches(matches, limit=10):
    matches = matches or []
    if not matches:
        print(colors.muted("  no known vulnerable components matched\n"))
        return
    print(colors.bold(f"  {len(matches)} match(es):"))
    for m in matches[:limit]:
        score = m.get("cvss", 0)
        cf = colors.cvss_color(score)
        cve = m.get("cve") or "n/a"
        title = (m.get("title") or "")[:60]
        print(f"    {cf(f'[{score:>4}]')} {cf(cve):<20} "
              f"{m.get('plugin', '?'):<38} {title}")
    if len(matches) > limit:
        print(colors.muted(f"    ... +{len(matches) - limit} more"))
    print()


# ─────────────────────────── shell ───────────────────────────

def print_shell(shell):
    if not shell:
        print(colors.fail("[!] shell: no result"))
        return
    if shell.get("success"):
        print(colors.ok(f"[+] shell live: {shell.get('url')}"))
        print(colors.ok(f"[+] password:   {shell.get('password')}"))
        print(colors.info(f"[+] usage:      curl -d 'auth=PW&cmd=id' {shell.get('url')}'"))
    else:
        print(colors.fail(f"[-] shell deploy failed: {shell.get('error')}"))


# ─────────────────────────── verdict ───────────────────────────

def _verdict(r):
    if (r.get("shell") or {}).get("success"):
        return "SHELL", colors.ok
    if r.get("admin"):
        return "ADMIN", colors.ok
    if (r.get("cracked") or {}).get("cracked"):
        return "CREDS", colors.warn
    if r.get("matches"):
        return "VULNS-ONLY", colors.warn
    return "NOTHING", colors.fail


def print_result(r):
    verdict, vfn = _verdict(r)
    print()
    print(colors.bold("== result =="))
    print(f"  verdict:  {vfn(verdict)}")
    print(f"  elapsed:  {r.get('elapsed')}s")

    ex = r.get("exploit")
    if ex:
        print(f"  exploit:  {ex.get('type')} via {ex.get('module', '?')}")

    cracked = (r.get("cracked") or {}).get("cracked") or {}
    if cracked:
        for h, p in cracked.items():
            print(f"  cracked:  {colors.ok(h)} -> {colors.ok(p)}")

    if r.get("admin"):
        a = r["admin"]
        print(f"  admin:    {colors.ok(a['user'])} : {colors.ok(a['pass'])}")

    if r.get("shell"):
        s = r["shell"]
        if s.get("success"):
            print(f"  shell:    {colors.ok(s.get('url'))}")
            print(f"  password: {colors.ok(s.get('password'))}")
        else:
            print(f"  shell:    {colors.fail('failed')} — {s.get('error')}")


# ─────────────────────────── text report ───────────────────────────

def write_report(path, r):
    target = r.get("target", "?")
    elapsed = r.get("elapsed", 0)
    verdict, _ = _verdict(r)
    recon = r.get("recon") or {}
    matches = r.get("matches") or []
    attempts = r.get("attempts") or []
    cracked = (r.get("cracked") or {}).get("cracked") or {}
    admin = r.get("admin")
    shell = r.get("shell")

    L = []
    add = L.append

    add("=" * 78)
    add("  WIBEH4CK — report")
    add("=" * 78)
    add(f"  target:   {target}")
    add(f"  date:     {time.strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"  elapsed:  {elapsed}s")
    add(f"  verdict:  {verdict}")
    add("")

    add("-" * 78)
    add("  RECON")
    add("-" * 78)
    add(f"  WordPress:  {recon.get('wp_version') or '?'}")
    add(f"  WAF:        {recon.get('waf') or 'none detected'}")
    add(f"  REST API:   {'yes' if recon.get('rest_api') else 'no'}")
    users = ", ".join(u.get("slug", "?") for u in recon.get("users") or []) or "-"
    add(f"  Users:      {users}")

    plugins = recon.get("plugins") or []
    if plugins:
        add("")
        add(f"  Plugins ({len(plugins)}):")
        for p in plugins:
            slug = p.get("slug", "?")
            ver = p.get("version") or "?"
            n = sum(1 for m in matches if m.get("plugin") == slug)
            if n:
                tag = f"!! {n} CVE"
            elif "." not in str(ver):
                tag = "?? version looks fake"
            else:
                tag = "clean"
            add(f"    {slug:<42} {str(ver):<12} {tag}")

    add("")
    add("-" * 78)
    add(f"  VULNERABILITIES (top 10 of {len(matches)})")
    add("-" * 78)
    if not matches:
        add("  none matched")
    else:
        for m in matches[:10]:
            add(f"  [{m.get('cvss', 0):>4}] {m.get('cve') or 'n/a':<16} "
                f"{m.get('plugin', '?'):<38} {(m.get('title') or '')[:60]}")
        if len(matches) > 10:
            add(f"  ... +{len(matches) - 10} more")

    add("")
    add("-" * 78)
    add("  EXPLOITATION")
    add("-" * 78)
    ex = r.get("exploit")
    if ex:
        add(f"  module:   {ex.get('module', '?')}")
        add(f"  cve:      {ex.get('matched_cve', '?')}")
        add(f"  type:     {ex.get('type', '?')}")
        for u in ex.get("users") or []:
            add(f"  user:     {u.get('login')}  {u.get('hash')}")
    elif attempts:
        add("  no exploit succeeded")
        for a in attempts:
            add(f"    - {a.get('module')} on {a.get('plugin')}: "
                f"{a.get('status')} — {a.get('error', '')}")
    else:
        add("  not attempted")

    if cracked:
        add("")
        add("-" * 78)
        add("  CRACKED CREDENTIALS")
        add("-" * 78)
        for h, pw in cracked.items():
            add(f"  {h}  ->  {pw}")

    if admin:
        add("")
        add("-" * 78)
        add("  ADMIN ACCESS")
        add("-" * 78)
        add(f"  user: {admin.get('user')}")
        add(f"  pass: {admin.get('pass')}")

    if shell:
        add("")
        add("-" * 78)
        add("  WEBSHELL")
        add("-" * 78)
        if shell.get("success"):
            add(f"  url:      {shell.get('url')}")
            add(f"  password: {shell.get('password')}")
            add(f"  usage:    curl -d 'auth=PW&cmd=id' {shell.get('url')}")
        else:
            add(f"  failed:   {shell.get('error')}")


    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def export_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
