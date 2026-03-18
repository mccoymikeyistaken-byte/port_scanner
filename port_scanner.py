import socket
import argparse
import time
import rich
import os
from scapy.all import IP, ICMP, sr1
import re
import save_reports
from threading import Lock
from colorama import init, Fore, Style
import asyncio 
import aiohttp

init(autoreset=True)

# for -h or --help
parser = argparse.ArgumentParser(description="A simple port scanner.")

# host is required; port or range is optional (defaults to 1-1024)
parser.add_argument("host", help="The target host to scan.")
parser.add_argument(
    "ports",
    nargs="?",
    default="1-1024",
    help="A single port (e.g. 80) or a range (e.g. 1-1024)."
)
parser.add_argument(
    "-t","--timeout",
    type = float,
    default=0.3,
    help="Timeout per port in seconds (default: 0.3)"
)
parser.add_argument(
    "-w","--workers",
    type=int,
    default=min(200, (os.cpu_count() or 1) * 20),
    help="Number of threads (default: auto)"
)
parser.add_argument(
   "-o","--output",
   type=str,
   default="results.txt",
   help="Target file name to store result"
)
args = parser.parse_args()

open_ports = []
lock = Lock()
HTTP_PORTS = {80, 443, 8080, 8443, 3000, 8000}

def os_fingerprint(ip):
    try:
        # Need root/admin for raw packets
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=2, verbose=0)

        if not response:
            return "Unknown (no response)"

        ttl = response.ttl

        if ttl <= 64:
            return f"Linux/Unix (TTL={ttl})"
        elif ttl <= 128:
            return f"Windows (TTL={ttl})"
        elif ttl <= 255:
            return f"Cisco/Network device (TTL={ttl})"
        else:
            return f"Unknown (TTL={ttl})"

    except PermissionError:
        return "Unknown (run as root for OS detection)"
    except Exception:
        return "Unknown (fingerprint failed)"
    
def extract_keyword(banner,service):
   if not banner:
      return None
   
   patterns = [
        r"(OpenSSH[\s_/][\d.]+)",        # OpenSSH 8.9
        r"(Apache[\s/][\d.]+)",           # Apache 2.4.41
        r"(nginx[\s/][\d.]+)",            # nginx 1.18
        r"(ProFTPD[\s/][\d.]+)",          # ProFTPD 1.3.5
        r"(vsftpd[\s/][\d.]+)",           # vsftpd 3.0
        r"(Microsoft[\s\-\w]+[\d.]+)",    # Microsoft IIS 10.0
    ]
   
   for pattern in patterns:
      match = re.search(pattern,banner,re.IGNORECASE)
      if match:
        return re.sub(r"[_/]", " ", match.group(1))
      
   return service if service!="Unknown" else None

async def CVELookup(keyword, max_results=3):
    if not keyword:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                data = await response.json()

        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]
            cve_id = cve["id"]

            description = next(
                (d["value"] for d in cve["descriptions"] if d["lang"] == "en"),
                "No description"
            )

            severity = "N/A"
            score = "N/A"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                data_v31 = metrics["cvssMetricV31"][0]["cvssData"]
                severity = data_v31["baseSeverity"]
                score = data_v31["baseScore"]
            elif "cvssMetricV2" in metrics:
                data_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                severity = data_v2["baseSeverity"]
                score = data_v2["baseScore"]

            cves.append({
                "id": cve_id,
                "score": score,
                "severity": severity,
                "description": description[:120]
            })

        return cves

    except Exception:
        return []

def severity_color(severity):
   colors = {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.YELLOW,
        "MEDIUM":   Fore.CYAN,
        "LOW":      Fore.GREEN,
        "N/A":      Fore.WHITE
    }
   return colors.get(severity.upper(), Fore.WHITE)

async def grab_banner(reader, writer, port):
    banner = None
    first_line = None

    try:
        if port in HTTP_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()

        raw = await asyncio.wait_for(reader.read(1024), timeout=1.5)
        banner = raw.decode(errors="ignore").strip()
        first_line = banner.replace('\r\n', '\n').splitlines()[0]
    except:
        pass

    return first_line
         
async def scan_port(host,port,timeout,semaphore):
    async with semaphore:   
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return 

        # Port is open
        banner = await grab_banner(reader, writer, port)
        writer.close()
        await writer.wait_closed()

        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "Unknown"

        keyword = extract_keyword(banner, service)
        cves = await CVELookup(keyword)

        async with async_lock:
            open_ports.append((port, service, banner, cves))
            print(Fore.GREEN + f"  [+] Port {port:<6} open   ({service})")
            if banner:
                print(Fore.MAGENTA + f"      Banner : {banner[:60]}")
            if cves:
                print(Fore.YELLOW + f"      CVEs found: {len(cves)}")
                for cve in cves:
                    color = severity_color(cve['severity'])
                    print(color + f"        {cve['id']} | Score: {cve['score']} | {cve['severity']}")
                    print(Fore.WHITE + f"        {cve['description'][:80]}")


    

async def scan_ports(host, start_port,end_port,timeout,workers):
    print(Fore.CYAN + f"\n  [*] Target   : {host}")
    print(Fore.CYAN + f"  [*] Range    : {start_port} - {end_port}")
    print(Fore.CYAN + f"  [*] Threads  : {workers}")
    print(Fore.CYAN + f"  [*] Timeout  : {timeout}s")
    print(Fore.YELLOW + f"\n  Scanning...\n")

    semaphore = asyncio.Semaphore(workers)  

    tasks = [
        scan_port(host, port, timeout, semaphore)
        for port in range(start_port, end_port + 1)
    ]

    await asyncio.gather(*tasks)  

def parse_port_range(port_range):
    try:
        if "-" in port_range:
         start_port, end_port = map(int, port_range.split("-"))
         return start_port, end_port
        else:
         start_port = end_port = int(port_range)
         return start_port, end_port
    except ValueError:
        print(Fore.RED + "[!] Invalid port format. Use '80' or '1-1024'.")
        exit(1)

# scan_port(target,80)
# scan_ports(target,1,1024)
def resolve_host(host):
   try:
        ip = socket.gethostbyname(host)
        print(Fore.CYAN + f"\n  [*] Resolved : {host} → {ip}")
        return ip
   except socket.gaierror:
        print(Fore.RED + f"\n  [!] Could not resolve host: {host}")
        exit(1)

def validate_port_range(start_port,end_port):
   if start_port < 0 or end_port > 65535:
        print("Invalid port range. Please enter a valid range (0-65535).")
        exit(1)
   if start_port > end_port:
        print("Start port must be less than or equal to end port.")
        exit(1)

def print_summary(start_time,os_guess):
    elapsed = time.time() - start_time
    sorted_ports = sorted(open_ports)

    print(Fore.YELLOW + "\n  ─────────────────────────────────")
    print(Fore.YELLOW + "  SCAN SUMMARY")
    print(Fore.YELLOW + "  ─────────────────────────────────")
    print(Fore.CYAN   + f"  OS Guess : {os_guess}")        
    print(Fore.YELLOW + "  ─────────────────────────────────")

    if sorted_ports:
        for port, service, banner, cves in sorted_ports:  # ← 4 values
            print(Fore.GREEN + f"  {port:<6} open   {service:<12} {banner or 'No banner'}")
            if cves:
                for cve in cves:
                    color = severity_color(cve['severity'])
                    print(color + f"    └─ {cve['id']} | Score: {cve['score']} | {cve['severity']}")
    else:
        print(Fore.RED + "  No open ports found.")

    print(Fore.CYAN + f"\n  [*] {len(sorted_ports)} open port(s) found")
    print(Fore.CYAN + f"  [*] Scan completed in {elapsed:.2f} seconds")
    print(Fore.YELLOW + "  ─────────────────────────────────\n")

async_lock = asyncio.Lock() 

async def main():
    start_time = time.time()
    start_port, end_port = parse_port_range(args.ports)
    validate_port_range(start_port, end_port)
    target_ip = resolve_host(args.host)

    os_guess = os_fingerprint(target_ip)
    print(Fore.CYAN + f"  [*] OS Guess : {os_guess}")

    await scan_ports(target_ip, start_port, end_port, args.timeout, args.workers)
    print_summary(start_time, os_guess)
    save_reports.save_report(args.output, target_ip, os_guess, start_time, open_ports)

asyncio.run(main())
