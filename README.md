# Vulnerability Scanner

A simple vulnerability scanner that scans for open ports, known vulnerabilities, and performs vulnerability verification.

## Features

-   Scans for open ports on a target host.
-   Identifies services running on the open ports.
-   Queries the Shodan CVEDB API for known vulnerabilities.
-   Uses the `nmap-vulners` script to perform vulnerability verification.

## Installation

1.  Clone this repository.
2.  Install the Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Install the `nmap-vulners` script. You need to find your nmap scripts directory and clone the repository there.
    ```bash
    # Find your nmap scripts path
    # e.g., /usr/share/nmap/scripts/
    sudo git clone https://github.com/vulnersCom/nmap-vulners.git <your_nmap_scripts_path>/nmap-vulners
    sudo nmap --script-updatedb
    ```

## Usage

To run a scan, use the following command:

```bash
python3 main.py <target_host>
```

To also run the vulnerability verification scripts, use the `--verify` flag:

```bash
python3 main.py --verify <target_host>
```
