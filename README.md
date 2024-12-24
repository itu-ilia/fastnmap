# FastNmap

A multi-threaded Nmap scanner that divides port scanning into 100 concurrent threads for faster scanning.

## Features

- Scans all ports (1-65535) using 100 parallel threads
- Supports both TCP and UDP scanning
- Creates both text and CSV reports
- Shows real-time progress for each thread
- Automatically sorts and combines results

## Requirements

- Python 3.x
- Nmap installed on your system
- Root/sudo privileges (for SYN and UDP scanning)

## Usage

```bash
sudo python3 nmap_threaded_scan.py <target>
```

Example:
```bash
sudo python3 nmap_threaded_scan.py example.com
```

## Output

The script creates two output files:
1. Text report (target_YYYYMMDD_HHMMSS.txt) - Contains full scan details
2. CSV report (target_YYYYMMDD_HHMMSS.csv) - Contains just the port information

### CSV Format
```csv
Port,Protocol,State,Service
80,tcp,open,http
443,tcp,open,https
53,udp,open,domain
```

## Scan Parameters

The script uses the following nmap parameters:
```
-T3 -n -Pn -sS -sU --open --max-retries 5 --initial-rtt-timeout 1s --max-rtt-timeout 2s --min-parallelism 50 --max-parallelism 150 --stats-every 30s
```

- T3: Normal timing template
- n: No DNS resolution
- Pn: Skip host discovery
- sS: TCP SYN scan
- sU: UDP scan
- max-retries 5: Retry each port up to 5 times
- Adjustable timing parameters for reliability
- Parallelism settings for performance

## Note

This script requires root/sudo privileges due to the use of SYN and UDP scanning. 