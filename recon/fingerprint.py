import re
from core.waf import detect


def fingerprint(target, http):
    t = target.rstrip("/")
    out = {"target": t, "wp_version": None, "plugins": [], "themes": [],
           "users": [], "waf": None, "rest_api": False}

    # wp version — try three paths
    probes = [
        ("/readme.html", r"Version\s+([\d.]+)"),
        ("/wp-includes/version.php", r"wp_version\s*=\s*['\"]([\d.]+)['\"]"),
        ("/", r'<meta name="generator" content="WordPress ([\d.]+)"'),
    ]
    for path, rx in probes:
        try:
            r = http.get(t + path)
            m = re.search(rx, r.text, re.IGNORECASE)
            if m:
                out["wp_version"] = m.group(1)
                break
        except Exception:
            pass

    # rest api
    try:
        r = http.get(t + "/wp-json/")
        if r.status_code == 200 and "wp/v2" in r.text:
            out["rest_api"] = True
    except Exception:
        pass

    # users
    try:
        r = http.get(t + "/wp-json/wp/v2/users")
        if r.status_code == 200:
            for u in r.json():
                out["users"].append({"id": u.get("id"), "slug": u.get("slug"),
                                     "name": u.get("name")})
    except Exception:
        pass

    # plugins — passive scan of homepage
    try:
        r = http.get(t + "/")
        slugs = set(re.findall(r"/wp-content/plugins/([^/\"'?]+)/", r.text))
        themes = set(re.findall(r"/wp-content/themes/([^/\"'?]+)/", r.text))
        for slug in slugs:
            out["plugins"].append(_probe_plugin(t, http, slug))
        for slug in themes:
            out["themes"].append(_probe_plugin(t, http, slug, kind="themes"))
    except Exception:
        pass

    # waf
    try:
        r = http.get(t + "/")
        out["waf"] = detect(r)
    except Exception:
        pass

    return out


def _probe_plugin(base, http, slug, kind="plugins"):
    entry = {"slug": slug, "version": None}
    for fname in ("readme.txt", "README.txt", "changelog.txt"):
        try:
            r = http.get(f"{base}/wp-content/{kind}/{slug}/{fname}")
            if r.status_code == 200:
                m = re.search(r"(?:stable tag|version):\s*([\d.]+)", r.text, re.IGNORECASE)
                if m:
                    entry["version"] = m.group(1)
                    break
        except Exception:
            pass
    return entry
