import subprocess
import sys
import os
import threading
from datetime import datetime
import re
import csv

# Global variables
found_ports = set()  # Using set to avoid duplicates
ports_lock = threading.Lock()

def parse_ports(output):
    """Extract port information from nmap output."""
    ports = []
    for line in output.split('\n'):
        if '/tcp' in line or '/udp' in line:
            if 'open' in line:
                # Extract just the port line
                ports.append(line.strip())
    return ports

def run_nmap_scan(start_port, end_port, thread_num, target):
    """Run Nmap scan for specified port range."""
    try:
        print(f"[+] Thread {thread_num}: Scanning ports {start_port}-{end_port}")
        
        # Run nmap command with exact parameters
        command = f"sudo nmap -T3 -n -Pn -sS -sU -p {start_port}-{end_port} --open --max-retries 5 --initial-rtt-timeout 1s --max-rtt-timeout 2s --min-parallelism 50 --max-parallelism 150 --stats-every 30s {target}"
                    

        process = subprocess.run(command.split(), capture_output=True, text=True)
        
        # Process output
        if process.returncode == 0 and 'open' in process.stdout:
            ports = parse_ports(process.stdout)
            with ports_lock:
                for port in ports:
                    found_ports.add(port)
            print(f"[+] Thread {thread_num}: Found {len(ports)} open ports!")
        else:
            print(f"[+] Thread {thread_num}: No open ports found")
            
    except Exception as e:
        print(f"[-] Thread {thread_num}: Error - {str(e)}")

def write_csv_report(ports, target, csv_file, scan_info):
    """Write scan results to CSV file."""
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # Write port information headers
        writer.writerow(['Port', 'Protocol', 'State', 'Service'])
        
        # Write port information
        for port_info in sorted(ports, key=lambda x: int(x.split('/')[0])):
            # Parse port line (e.g., "80/tcp   open  http")
            parts = port_info.split()
            port_proto = parts[0].split('/')
            port = port_proto[0]
            protocol = port_proto[1]
            state = parts[1]
            service = parts[2] if len(parts) > 2 else ''
            writer.writerow([port, protocol, state, service])

def main(target):
    # Check for sudo privileges
    if os.geteuid() != 0:
        print("[-] This script requires sudo privileges to run nmap with SYN and UDP scans.")
        print("[-] Please run with sudo.")
        sys.exit(1)

    # Create output filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    txt_file = f"{target}_{timestamp}.txt"
    csv_file = f"{target}_{timestamp}.csv"
    
    # Calculate port ranges for 100 threads
    total_ports = 65535
    chunk_size = total_ports // 100
    ranges = []
    start = 1
    
    # Create 100 ranges
    for i in range(100):
        if i == 99:  # Last chunk gets remaining ports
            end = 65535
        else:
            end = start + chunk_size - 1
        ranges.append((start, end))
        start = end + 1
    
    print(f"[+] Starting scan with {len(ranges)} threads")
    print(f"[+] Each thread will scan approximately {chunk_size} ports")
    
    scan_start_time = datetime.now()
    
    # Start threads
    threads = []
    for i, (start, end) in enumerate(ranges, 1):
        thread = threading.Thread(
            target=run_nmap_scan,
            args=(start, end, i, target)
        )
        thread.start()
        threads.append(thread)
    
    # Wait for all threads
    for thread in threads:
        thread.join()
    
    scan_end_time = datetime.now()
    scan_duration = scan_end_time - scan_start_time

    # Prepare scan information
    scan_info = {
        'start_time': scan_start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'end_time': scan_end_time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration': str(scan_duration),
        'command': 'nmap -T3 -n -Pn -sS -sU -p- --open --max-retries 3 --max-rtt-timeout 400ms --initial-rtt-timeout 300ms --min-parallelism 50'
    }
    
    # Write text report
    with open(txt_file, 'w') as f:
        f.write(f"NMAP SCAN REPORT FOR {target}\n")
        f.write(f"Scan started: {scan_info['start_time']}\n")
        f.write(f"Scan completed: {scan_info['end_time']}\n")
        f.write(f"Scan duration: {scan_info['duration']}\n")
        f.write(f"Command: {scan_info['command']}\n")
        f.write(f"Threads: 100 (approximately {chunk_size} ports per thread)\n")
        f.write("-" * 60 + "\n")
        
        if found_ports:
            f.write("PORT      STATE  SERVICE\n")
            # Sort ports numerically
            sorted_ports = sorted(found_ports, key=lambda x: int(x.split('/')[0]))
            for port in sorted_ports:
                f.write(f"{port}\n")
        else:
            f.write("No open ports found.\n")
    
    # Write CSV report
    write_csv_report(found_ports, target, csv_file, scan_info)
    
    print(f"\n[+] Scan completed in {scan_duration}!")
    print(f"[+] Results saved to:")
    print(f"    - Text report: {txt_file}")
    print(f"    - CSV report: {csv_file}")
    
    # Print results to console
    if found_ports:
        print("\nOpen ports found:")
        print("PORT      STATE  SERVICE")
        for port in sorted(found_ports, key=lambda x: int(x.split('/')[0])):
            print(port)
    else:
        print("\nNo open ports found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 nmap_threaded_scan.py <target>")
        sys.exit(1)
        
    target = sys.argv[1]
    # Remove https:// if present
    target = target.replace('https://', '').replace('http://', '')
    print(f"[+] Starting scan of {target}")
    main(target) 