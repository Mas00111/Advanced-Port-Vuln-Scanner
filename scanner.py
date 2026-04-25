import socket
import threading
import json
import os
from datetime import datetime
from colorama import Fore, Style, init

from utils import get_service

init(autoreset=True)


VULNERABLE_SERVICES = {
    "Telnet": "HIGH",
    "FTP": "MEDIUM",
    "SMB": "HIGH",
    "RDP": "HIGH",
    "HTTP": "LOW",
    "SSH": "LOW"
}

def show_banner():
    print(Fore.RED + """
╔══════════════════════════════════════════════╗
║     Advanced PORT SCANNER + VULN CHECKER     ║
║        
          Created By MAS          ║
╚══════════════════════════════════════════════╝
""")

show_banner()


target = input(Fore.BLUE + "Enter target IP: " + Style.RESET_ALL)
start_port = int(input(Fore.BLUE + "Start port: " + Style.RESET_ALL))
end_port = int(input(Fore.BLUE + "End port: " + Style.RESET_ALL))

print(Fore.MAGENTA + f"\n[+] Target: {target}")
print(f"[+] Range: {start_port}-{end_port}")
print(f"[+] Scan started: {datetime.now()}\n")


print_lock = threading.Lock()
results = []


def grab_banner(sock):
    try:
        sock.settimeout(2)
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return None


def analyze_risk(service, banner):
    risk = VULNERABLE_SERVICES.get(service, "LOW")

    if banner:
        b = banner.lower()

        if "apache 2.2" in b:
            risk = "HIGH"
        elif "nginx/1.10" in b:
            risk = "MEDIUM"
        elif "openssh_5" in b:
            risk = "HIGH"
        elif "ftp" in b:
            risk = "MEDIUM"

    return risk


def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)

            if sock.connect_ex((target, port)) == 0:
                service = get_service(port)
                banner = grab_banner(sock)
                risk = analyze_risk(service, banner)

                data = {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "risk": risk
                }

                results.append(data)

                with print_lock:
                    if risk == "HIGH":
                        color = Fore.RED
                    elif risk == "MEDIUM":
                        color = Fore.BLUE
                    else:
                        color = Fore.GREEN

                    print(color + f"[OPEN] {port} → {service} [{risk} RISK]")

                    if banner:
                        print(Fore.CYAN + f"    └─ Banner: {banner}")

    except:
        pass


def save_results():
    os.makedirs("results", exist_ok=True)

    file_path = f"results/scan_{target.replace('.', '_')}.json"

    with open(file_path, "w") as f:
        json.dump(results, f, indent=4)

    print(Fore.YELLOW + f"\n[+] Results saved to {file_path}")


def run_scan():
    print(Fore.BLUE + "\n[+] Scanning in progress...\n")

    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

  
    high = len([r for r in results if r["risk"] == "HIGH"])
    medium = len([r for r in results if r["risk"] == "MEDIUM"])
    low = len([r for r in results if r["risk"] == "LOW"])

    print(Fore.MAGENTA + "\n[+] Risk Summary:")
    print(f"    HIGH: {high}")
    print(f"    MEDIUM: {medium}")
    print(f"    LOW: {low}")

    save_results()

    print(Fore.GREEN + "\n[✓] Scan completed!")


if __name__ == "__main__":
    run_scan()