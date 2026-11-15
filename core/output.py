import json

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
    print(BANNER)
    print("  wibeh4ck — WordPress chain for CTF \n")


def print_recon(r):
    print(f"  target:     {r.get('target')}")
    print(f"  wp version: {r.get('wp_version') or '?'}")
    print(f"  waf:        {r.get('waf') or 'none detected'}")
    print(f"  users:      {', '.join(u['slug'] for u in r.get('users', [])) or '-'}")
    if r.get("plugins"):
        print("  plugins:")
        for p in r["plugins"]:
            print(f"    - {p['slug']:<30} {p.get('version') or '?'}")
    print()


def print_matches(matches):
    if not matches:
        print("  no known vulnerable components matched\n")
        return
    print(f"  {len(matches)} match(es):")
    for m in matches:
        print(f"    [{m['cvss']:>4}] {m.get('cve') or 'n/a':<16} {m['plugin']} {m['plugin_version']} — {m.get('title','')[:60]}")
    print()


def print_result(r):
    ex = r.get("exploit")
    print("\n== result ==")
    if ex:
        print(f"  exploit:  {ex.get('type')} via {ex.get('module', '?')}")
        for u in ex.get("users", []):
            print(f"  user:     {u['login']}  {u['hash']}")
    if r.get("cracked", {}).get("cracked"):
        for h, p in r["cracked"]["cracked"].items():
            print(f"  cracked:  {h} -> {p}")
    if r.get("admin"):
        print(f"  admin:    {r['admin']['user']} : {r['admin']['pass']}")
    if r.get("shell"):
        print(f"  shell:    {r['shell'].get('url')}  pw={r['shell'].get('password')}")
    print(f"  elapsed:  {r['elapsed']}s")


def print_shell(shell):
    if shell.get("success"):
        print(f"[+] shell live: {shell['url']}")
        print(f"[+] password:   {shell['password']}")
        print(f"[+] usage:      curl -d 'auth=PW&cmd=id' {shell['url']}")
    else:
        print(f"[-] shell deploy failed: {shell.get('error')}")


def export_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
