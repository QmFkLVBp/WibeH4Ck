"""TEMPLATE — скопируй в <name>.py, заполни run()."""
from framework import Module, C


class MyExploit(Module):
    name = "myexploit"
    description = "short description"
    author = "you"

    options = {
        "TARGET": {"value": None, "required": True, "description": "Target URL/IP"},
        "RPORT": {"value": "80", "required": True, "description": "Target port"},
        "LHOST": {"value": None, "required": False, "description": "Your IP"},
        "LPORT": {"value": "4444","required": False,"description": "Your port"},
    }

    def run(self):
        target = self.get("TARGET")
        rport = self.get("RPORT")
        print(f"{C.Y}[*] Exploiting {target}:{rport}...{C.END}")
        # --- твоя логика здесь ---
        # from framework import interactive_shell
        # interactive_shell(sock, manager=self.sessions)

        print(f"{C.G}[+] done{C.END}")
