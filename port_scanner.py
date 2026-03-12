import socket
import argparse
import time
from threading import Thread
from concurrent.futures import ThreadPoolExecutor

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

args = parser.parse_args()

def scan_port(host,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(0.5)
    target_ip = socket.gethostbyname(host)
    connection_status = sock.connect_ex((target_ip,port))
    try:
        service = socket.getservbyport(port)
    except OSError:
        service = "Unknown"

    if connection_status == 0:
        print(f"[+] Port {port} is open (service: {service})")
    else:
        print(f"[-] Port {port} is closed (service: {service})")

    sock.close()

    

def scan_ports(host, start_port,end_port):
    if start_port < 0 or end_port > 65535:
        print("Invalid port range. Please enter a valid range (0-65535).")
        return
    if start_port > end_port:
        print("Start port must be less than or equal to end port.")
        return
    print(f"Scanning ports {start_port} to {end_port} on {host}...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, host, port)

def parse_port_range(port_range):
    try:
        if "-" in port_range:
         start_port, end_port = map(int, port_range.split("-"))
         return start_port, end_port
        else:
         start_port = end_port = int(port_range)
         return start_port, end_port
    except ValueError:
        print("Invalid port range format. Please use the format 'start-end' (e.g., 1-1024).")
        exit(1)
# scan_port(target,80)
# scan_ports(target,1,1024)


start_time = time.time()
start_port, end_port = parse_port_range(args.ports)
scan_ports(args.host, start_port, end_port)
print(f"Scan completed in {time.time() - start_time:.2f} seconds")