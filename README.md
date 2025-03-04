# vahana 

**Author:** Manoj Prakash J  
**Disclaimer:** This tool is intended for authorized pentesting/educational purposes only. Use responsibly.

## Overview

This tool is a multi-functional file transfer and directory sharing utility written in Python. It provides multiple file transfer methods with integrity verification and supports advanced directory operations such as zipping (with an optional manifest of file hashes) and serving directories over HTTP/HTTPS. When serving directories over HTTPS, the tool can automatically generate a self-signed TLS certificate if you do not provide your own.

## Features

- **File Transfers with Integrity Verification:**
  - **HTTP/S:** Download or upload files using Python’s `requests` module.
  - **SCP:** Securely transfer files using SSH (requires Paramiko and SCP modules).
  - **wget, curl, and PHP:** Download files via popular command-line utilities.
  - Generates a SHA256 hash of files to ensure integrity after transfers.

- **Directory Operations:**
  - **Zip a Directory:** Compress an entire directory into a ZIP file. Optionally generate a manifest (`manifest.txt`) that lists each file’s SHA256 hash.
  - **Serve a Directory:** Launch a simple HTTP server to share a directory.
    - **HTTPS Support:** Use the `--tls` flag to enable HTTPS.
      - If `--tls` is provided without specifying certificate and key files (`--tls_cert` and `--tls_key`), a self-signed certificate is automatically generated.
      - If certificate paths are provided, the tool will use those files instead.
    - Allows you to specify the host and port.

## Requirements

- **Python 3.6+**
- **OpenSSL:** Required for auto-generating self-signed TLS certificates.
- **Optional Python Modules:**  
  - `requests` (install via `pip install requests`)
  - `paramiko` and `scp` (for SCP functionality; install via `pip install paramiko scp`)

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/manojprakashj/Vahana.git
   cd Vahana

2. **Make the Script Executable:**

   ```bash
   chmod +x Vahana.py

3. **Install Dependencies:**

   ```bash
   pip install requests paramiko scp

## Usage

   ```bash
   Vahana.py --help
