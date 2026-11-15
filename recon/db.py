import json
import re


def load_db(path):
    with open(path) as f:
        return json.load(f)


def _to_tuple(v):
    parts = []
    for p in re.split(r"[.\-+]", v):
        m = re.match(r"^(\d+)", p)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts)


def _cmp(a, b):
    a, b = _to_tuple(a), _to_tuple(b)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


def _in_range(version, spec):
    frm = spec.get("from", "*")
    to = spec.get("to", "*")
    f_inc = spec.get("from_inc", True)
    t_inc = spec.get("to_inc", True)
    if frm != "*":
        c = _cmp(version, frm)
        if c < 0 or (c == 0 and not f_inc):
            return False
    if to != "*":
        c = _cmp(version, to)
        if c > 0 or (c == 0 and not t_inc):
            return False
    return True


def match_vulns(plugins, db):
    matches = []
    for p in plugins:
        slug, ver = p.get("slug"), p.get("version")
        if not slug or not ver:
            continue
        for uuid, entry in db.items():
            for soft in entry.get("software", []):
                if soft.get("type") == "plugin" and soft.get("slug") == slug:
                    for spec in soft.get("affected_versions", []):
                        if _in_range(ver, spec):
                            matches.append({
                                "uuid": uuid,
                                "cve": entry.get("cve"),
                                "title": entry.get("title", ""),
                                "cvss": float(entry.get("cvss", {}).get("score", 0) or 0),
                                "plugin": slug,
                                "plugin_version": ver,
                                "vuln_type": entry.get("cwe", {}).get("name", ""),
                            })
                            break
                    break
    deduped = {}
    for m in matches:
        deduped[m["uuid"]] = m
    return sorted(deduped.values(), key=lambda x: -x["cvss"])
