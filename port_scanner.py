# ============================================
#   🔍 PORT SCANNER
# ============================================

import socket
import threading
from datetime import datetime

# ── Common ports and their services ──────────────────────────
COMMON_PORTS = {
    21:   "FTP (File Transfer Protocol)",
    22:   "SSH (Secure Shell)",
    23:   "Telnet",
    25:   "SMTP (Email Sending)",
    53:   "DNS (Domain Name System)",
    80:   "HTTP (Web Server)",
    110:  "POP3 (Email Receiving)",
    135:  "RPC (Remote Procedure Call)",
    139:  "NetBIOS",
    143:  "IMAP (Email)",
    443:  "HTTPS (Secure Web Server)",
    445:  "SMB (File Sharing)",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL (Database)",
    5900: "VNC (Remote Desktop)",
    6379: "Redis (Database)",
    8080: "HTTP Alternate (Web Server)",
    8443: "HTTPS Alternate",
    27017:"MongoDB (Database)",
}

# Thread-safe list to store open ports
open_ports = []
lock = threading.Lock()


def display_banner():
    print("\n" + "="*55)
    print("   🔍 PORT SCANNER")
    print("="*55)
    print("   Project 3 - Cybersecurity Learning Series")
    print("="*55)


def display_menu():
    print("\n  What would you like to do?")
    print("  [1] Scan common ports (fast)")
    print("  [2] Scan a custom port range")
    print("  [3] Scan a single port")
    print("  [4] Learn how Port Scanning works")
    print("  [5] Exit")


def get_service(port):
    """Return service name for a known port."""
    return COMMON_PORTS.get(port, "Unknown Service")


def scan_port(host, port):
    """Try to connect to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:  # Port is open!
            with lock:
                open_ports.append(port)
    except:
        pass


def resolve_host(target):
    """Convert hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def print_progress(current, total):
    """Show a simple progress bar."""
    percent = int((current / total) * 100)
    bar = "█" * (percent // 5) + "░" * (20 - percent // 5)
    print(f"\r  Progress: [{bar}] {percent}% ({current}/{total} ports)", end="")


def scan_ports(host, ports):
    """Scan a list of ports using threads for speed."""
    global open_ports
    open_ports = []  # Reset results

    print(f"\n  ⏳ Scanning {host}...")
    print(f"  📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    threads = []
    total = len(ports)

    for i, port in enumerate(ports):
        t = threading.Thread(target=scan_port, args=(host, port))
        threads.append(t)
        t.start()

        # Show progress every 10 ports
        if i % 10 == 0:
            print_progress(i + 1, total)

        # Limit active threads to avoid overload
        if len(threads) >= 100:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads
    for t in threads:
        t.join()

    print_progress(total, total)
    print("\n")

    return sorted(open_ports)


def display_results(host, ip, open_ports, scan_time):
    """Display scan results in a clean table."""
    print("="*55)
    print(f"  📋 SCAN RESULTS")
    print("="*55)
    print(f"  Target   : {host}")
    print(f"  IP       : {ip}")
    print(f"  Scan Time: {scan_time:.2f} seconds")
    print(f"  Open Ports Found: {len(open_ports)}")
    print("="*55)

    if open_ports:
        print(f"\n  {'PORT':<8} {'STATUS':<10} {'SERVICE'}")
        print("  " + "-"*50)
        for port in open_ports:
            service = get_service(port)
            print(f"  {port:<8} {'OPEN':<10} {service}")

        print("\n  ⚠️  Open ports can be potential entry points for attackers!")
        print("  ✅ Only keep ports open that you actually need.")
    else:
        print("\n  ✅ No open ports found — target appears well protected!")

    print("="*55 + "\n")


def learn_mode():
    print("\n" + "="*55)
    print("  📚 HOW PORT SCANNING WORKS")
    print("="*55)
    print("""
  WHAT IS A PORT?
  Think of an IP address like a building address.
  Ports are like individual doors in that building.
  Each door (port) leads to a different service.

  Common "doors" (ports):
    Port 80  → HTTP  (regular websites)
    Port 443 → HTTPS (secure websites)
    Port 22  → SSH   (remote server access)
    Port 21  → FTP   (file transfers)
    Port 3306→ MySQL (databases)

  HOW DOES SCANNING WORK?
  The scanner tries to "knock" on each door:
    - If the door opens → port is OPEN ✅
    - If no response   → port is CLOSED ❌
    - If blocked       → port is FILTERED 🚫

  WHY DO HACKERS SCAN PORTS?
  Open ports = potential entry points.
  If port 22 is open, they might try to brute
  force the SSH password to get inside.

  WHY DO DEFENDERS SCAN PORTS?
  Security teams scan their OWN systems to find
  ports they forgot to close — before attackers do!

  TOOLS LIKE THIS:
  Professional tool: Nmap (Network Mapper)
  This project is a simple version of Nmap!

  ⚠️  LEGAL WARNING:
  Only scan systems you OWN or have permission
  to scan. Scanning others without permission
  is ILLEGAL in most countries.
    """)
    print("="*55 + "\n")


def main():
    display_banner()
    print("\n  ⚠️  LEGAL WARNING: Only scan systems you own")
    print("  or have explicit permission to scan!")

    while True:
        display_menu()
        choice = input("\n  Choose an option (1-5): ").strip()

        if choice in ["1", "2", "3"]:
            target = input("\n  Enter target (IP or hostname): ").strip()

            # Resolve hostname to IP
            ip = resolve_host(target)
            if not ip:
                print(f"\n  ❌ Could not resolve '{target}'. Check the address and try again.")
                continue

            if ip != target:
                print(f"  ✅ Resolved: {target} → {ip}")

            start_time = datetime.now()

            if choice == "1":
                # Scan common ports
                ports = list(COMMON_PORTS.keys())
                print(f"\n  🔍 Scanning {len(ports)} common ports...")
                results = scan_ports(ip, ports)

            elif choice == "2":
                # Custom range
                try:
                    start = int(input("  Enter start port (e.g. 1): "))
                    end = int(input("  Enter end port (e.g. 1024): "))
                    if start < 1 or end > 65535 or start > end:
                        print("  ❌ Invalid range. Ports must be between 1 and 65535.")
                        continue
                    ports = list(range(start, end + 1))
                    print(f"\n  🔍 Scanning ports {start} to {end} ({len(ports)} ports)...")
                    results = scan_ports(ip, ports)
                except ValueError:
                    print("  ❌ Please enter valid numbers.")
                    continue

            elif choice == "3":
                # Single port
                try:
                    port = int(input("  Enter port number: "))
                    if port < 1 or port > 65535:
                        print("  ❌ Port must be between 1 and 65535.")
                        continue
                    results = scan_ports(ip, [port])
                except ValueError:
                    print("  ❌ Please enter a valid number.")
                    continue

            end_time = datetime.now()
            scan_time = (end_time - start_time).total_seconds()
            display_results(target, ip, results, scan_time)

        elif choice == "4":
            learn_mode()

        elif choice == "5":
            print("\n  👋 Goodbye! Keep learning \n")
            break

        else:
            print("\n  ❌ Invalid option. Please choose 1-5.")

        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()