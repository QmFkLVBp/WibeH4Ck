import urllib.parse


SIGNATURES = {
    "cloudflare":  ["cf-ray", "cloudflare"],
    "sucuri":      ["x-sucuri-id", "sucuri"],
    "wordfence":   ["wordfence", "wf-"],
    "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
    "akamai":      ["akamai", "ak-bmsc"],
    "f5":          ["bigip", "f5 networks"],
}


def detect(response):
    headers = {k.lower(): str(v).lower() for k, v in response.headers.items()}
    body = response.text[:12000].lower()
    for waf, sigs in SIGNATURES.items():
        for sig in sigs:
            if any(sig in k or sig in v for k, v in headers.items()) or sig in body:
                return waf
    return None


def variants(payload, waf):
    """Yield payload transformations suitable for the detected WAF."""
    yield payload
    if waf in ("modsecurity", "wordfence", "cloudflare"):
        yield payload.replace(" ", "/**/")
        yield payload.replace(" ", "+")
        yield urllib.parse.quote(payload, safe="")
    if waf in ("cloudflare", "akamai"):
        yield payload.replace(" ", "%09").replace("=", "%3D")
        yield "".join(f"%{ord(c):02x}" for c in payload)
