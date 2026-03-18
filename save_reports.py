import json
import time
from datetime import datetime
from colorama import Fore
import json
from datetime import datetime

def save_report(filename, target, os_guess, start_time,open_ports):
    elapsed = time.time() - start_time
    sorted_ports = sorted(open_ports)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if filename.endswith(".json"):
        data = {
            "target": target,
            "timestamp": timestamp,
            "os_guess": os_guess,
            "scan_duration": f"{elapsed:.2f}s",
            "open_ports": []
        }

        for port, service, banner, cves in sorted_ports:
            data["open_ports"].append({
                "port": port,
                "service": service,
                "banner": banner or "No banner",
                "cves": cves  
            })

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

    else:
        lines = []
        lines.append("=" * 50)
        lines.append("         PORT SCANNER REPORT")
        lines.append("=" * 50)
        lines.append(f"  Target    : {target}")
        lines.append(f"  Timestamp : {timestamp}")
        lines.append(f"  OS Guess  : {os_guess}")
        lines.append(f"  Duration  : {elapsed:.2f}s")
        lines.append(f"  Open Ports: {len(sorted_ports)}")
        lines.append("=" * 50)
        lines.append("")

        if sorted_ports:
            for port, service, banner, cves in sorted_ports:
                lines.append(f"  [{port}] {service}")
                lines.append(f"    Banner : {banner or 'No banner'}")
                if cves:
                    lines.append(f"    CVEs   : {len(cves)} found")
                    for cve in cves:
                        lines.append(f"      - {cve['id']} | Score: {cve['score']} | {cve['severity']}")
                        lines.append(f"        {cve['description'][:80]}")
                lines.append("")
        else:
            lines.append("  No open ports found.")

        with open(filename, "w") as f:
            f.write("\n".join(lines))

    print(Fore.CYAN + f"\n  [*] Report saved → {filename}")