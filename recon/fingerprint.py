# language: python, file: recon/fingerprint.py
import re
from core.waf import detect

def fingerprint(target, http):
    t = target.rstrip("/")
    out = {"target": t, "wp_version": None, "plugins": [], "themes": [], "users": [], "waf": None, "rest_api": False}

    # wp version — three probes
    probes = [
        ("/readme.html", r"Version\s+([\d.]+)"),
        ("/wp-includes/version.php", r"wp_version\s*=\s*['\"]([\d.]+)['\"]"),
        ("/", r'<meta name="generator" content="WordPress ([\d.]+)"'),
    ]
    for path, pat in probes:
        try:
            r = http.get(t + path)
            if r.status_code == 200:
                m = re.search(pat, r.text)
                if m:
                    out["wp_version"] = m.group(1)
                    break
        except Exception:
            continue

    # home page — plugins, themes, users, rest_api, waf
    try:
        home = http.get(t + "/")
        body = home.text
        out["waf"] = detect(home)
        out["rest_api"] = 'rel="https://api.w.org/"' in body

        slugs = set(re.findall(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/", body))
        for slug in sorted(slugs):
            ver = None
            try:
                rp = http.get(f"{t}/wp-content/plugins/{slug}/readme.txt")
                if rp.status_code == 200:
                    mv = re.search(r"Stable tag:\s*([\d.]+)", rp.text)
                    if mv:
                        ver = mv.group(1)
            except Exception:
                pass
            out["plugins"].append({"slug": slug, "version": ver})

        themes = set(re.findall(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", body))
        for th in sorted(themes):
            out["themes"].append({"slug": th})

        users = set(re.findall(r"/author/([a-zA-Z0-9_-]+)/", body))
        for u in sorted(users):
            out["users"].append({"slug": u})
    except Exception:
        pass

    # REST API user enumeration fallback
    if not out["users"]:
        try:
            rj = http.get(t + "/wp-json/wp/v2/users")
            if rj.status_code == 200:
                for u in rj.json():
                    if u.get("slug"):
                        out["users"].append({"slug": u["slug"]})
        except Exception:
            pass

    return out
