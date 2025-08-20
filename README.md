# Network Mapper

This project provides a simple network mapping tool that parses Nmap XML scan results to visualize network hosts and their open ports. It can be run as a command-line script or through a graphical user interface (GUI).

## Features

- Parses Nmap XML output files.
- Displays discovered hosts, IP addresses, hostnames, and open ports.
- Detects and lists local DNS servers from `/etc/resolv.conf`.
- Generates a visual network diagram using the `diagrams` library.
- Provides a user-friendly GUI to access all features.

## Setup

1.  **Prerequisites:**
    - Python 3.6+
    - Nmap (to generate the scan files)

2.  **Installation:**
    It is recommended to use a virtual environment to manage dependencies.

    ```bash
    # Create and activate a virtual environment (optional but recommended)
    python3 -m venv venv
    source venv/bin/activate

    # Install the required Python packages
    pip install -r network_mapper/requirements.txt
    ```

## Usage

Before running the tool, you need an Nmap scan result file in XML format.

1.  **Generate an Nmap Scan File:**
    Run an Nmap scan on your network and save the output to XML. For example:

    ```bash
    # Scan a local subnet and save the output to network_scan.xml
    nmap -sV -oX network_scan.xml 192.168.1.0/24
    ```
    Make sure the output file (`network_scan.xml`) is in the root directory of this project.

2.  **Running the GUI Application:**
    The easiest way to use the tool is via the GUI.

    ```bash
    python3 network_mapper/gui.py
    ```
    From the GUI, you can:
    - Click "Browse..." to select your Nmap XML file.
    - Click "Load and Scan" to parse the file and see the results.
    - Click "Generate Diagram" to create and view the network map.

3.  **Running the Command-Line Script:**
    If you prefer the command line, you can run the original script. The script is configured to look for `network_scan.xml` in the project's root directory.

    ```bash
    python3 network_mapper/mapper.py
    ```
    The script will print the discovered host information to the console and generate a `network_map.png` file if the `diagrams` library is correctly installed.
