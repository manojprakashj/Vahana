#!/usr/bin/env python3
import argparse
import base64
import subprocess
import sys
import os
import hashlib
import requests
import zipfile
import tempfile
try:
    import paramiko
    from scp import SCPClient
except ImportError:
    paramiko = None
    SCPClient = None
from http.server import SimpleHTTPRequestHandler, HTTPServer
def generate_self_signed_cert():
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.close()
    key_file.close()
    command = f"openssl req -x509 -nodes -newkey rsa:2048 -keyout {key_file.name} -out {cert_file.name} -days 365 -subj '/CN=localhost'"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"[HTTPS] Self-signed certificate generated:\n\tCert: {cert_file.name}\n\tKey: {key_file.name}")
        return cert_file.name, key_file.name
    except subprocess.CalledProcessError as e:
        print(f"[HTTPS] Failed to generate self-signed certificate: {e}")
        return None, None
def generate_hash(file_path, algo="sha256"):
    hash_func = getattr(hashlib, algo)()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"[Hash] Failed to generate hash for {file_path}: {e}")
        return None
def http_download(url, output):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(output, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[HTTP] File downloaded to: {output}")
        hash_val = generate_hash(output)
        if hash_val:
            print(f"[Hash] SHA256: {hash_val}")
    except Exception as e:
        print(f"[HTTP] Download failed: {e}")
def http_upload(url, file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        hash_val = generate_hash(file_path)
        print(f"[Hash] Local file SHA256: {hash_val}")
        b64_data = base64.b64encode(data)
        response = requests.post(url, data=b64_data)
        print(f"[HTTP] Upload complete. Response code: {response.status_code}")
    except Exception as e:
        print(f"[HTTP] Upload failed: {e}")
def scp_download(host, port, username, password, remote_file, local_file):
    if paramiko is None or SCPClient is None:
        print("[SCP] Required modules not installed. Run: pip install paramiko scp")
        return
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password)
        with SCPClient(ssh.get_transport()) as scp:
            scp.get(remote_file, local_file)
        print(f"[SCP] File downloaded from {host}:{remote_file} to {local_file}")
        ssh.close()
        hash_val = generate_hash(local_file)
        if hash_val:
            print(f"[Hash] SHA256: {hash_val}")
    except Exception as e:
        print(f"[SCP] Download failed: {e}")
def scp_upload(host, port, username, password, local_file, remote_file):
    if paramiko is None or SCPClient is None:
        print("[SCP] Required modules not installed. Run: pip install paramiko scp")
        return
    try:
        hash_val = generate_hash(local_file)
        print(f"[Hash] Local file SHA256: {hash_val}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password)
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(local_file, remote_file)
        print(f"[SCP] File uploaded to {host}:{remote_file} from {local_file}")
        ssh.close()
    except Exception as e:
        print(f"[SCP] Upload failed: {e}")
def wget_download(url, output):
    command = f"wget {url} -O {output}"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"[Wget] File downloaded to: {output}")
        hash_val = generate_hash(output)
        if hash_val:
            print(f"[Hash] SHA256: {hash_val}")
    except subprocess.CalledProcessError as e:
        print(f"[Wget] Download failed: {e}")
def curl_download(url, output):
    command = f"curl -o {output} {url}"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"[Curl] File downloaded to: {output}")
        hash_val = generate_hash(output)
        if hash_val:
            print(f"[Hash] SHA256: {hash_val}")
    except subprocess.CalledProcessError as e:
        print(f"[Curl] Download failed: {e}")
def php_download(url, output):
    command = f"""php -r '$file = file_get_contents("{url}"); file_put_contents("{output}",$file);'"""
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"[PHP] File downloaded to: {output}")
        hash_val = generate_hash(output)
        if hash_val:
            print(f"[Hash] SHA256: {hash_val}")
    except subprocess.CalledProcessError as e:
        print(f"[PHP] Download failed: {e}")
def zip_directory(directory, output_zip, generate_manifest=False):
    manifest_lines = []
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, start=directory)
                zipf.write(file_path, arcname)
                if generate_manifest:
                    hash_val = generate_hash(file_path)
                    manifest_lines.append(f"{arcname}: {hash_val}")
        if generate_manifest:
            manifest_content = "\n".join(manifest_lines)
            zipf.writestr("manifest.txt", manifest_content)
    print(f"[Zip] Directory '{directory}' zipped into '{output_zip}'")
    zip_hash = generate_hash(output_zip)
    if zip_hash:
        print(f"[Hash] Zip file SHA256: {zip_hash}")
def serve_directory(directory, host, port, use_tls=False, tls_cert=None, tls_key=None):
    import ssl
    os.chdir(directory)
    handler = SimpleHTTPRequestHandler
    httpd = HTTPServer((host, port), handler)
    protocol = "http"
    if use_tls:
        if tls_cert is None or tls_key is None:
            print("[HTTPS] --tls flag provided without certificate paths, generating self-signed certificate.")
            tls_cert, tls_key = generate_self_signed_cert()
        try:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=tls_cert, keyfile=tls_key, server_side=True)
            protocol = "https"
        except Exception as e:
            print(f"[HTTP Server] Failed to enable HTTPS: {e}")
            protocol = "http"
    print(f"[HTTP Server] Serving '{directory}' at {protocol}://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[HTTP Server] Shutting down.")
        httpd.server_close()
    except Exception as e:
        print(f"[HTTP Server] Error: {e}")
def main():
    help_text = (
        "Advanced File Transfer and Directory Sharing Tool for Linux\n\n"
        "This tool supports various file transfer methods (HTTP/S, SCP, wget, curl, PHP) with SHA256 "
        "integrity verification. It also offers directory operations:\n"
        "  - Zip a directory (optionally with a manifest of file hashes).\n"
        "  - Serve a directory via an HTTP or HTTPS server.\n\n"
        "HTTPS Support:\n"
        "  - To serve over HTTPS, include the --tls flag when using the 'dir serve' command.\n"
        "  - If you provide --tls along with --tls_cert and --tls_key, those files are used.\n"
        "  - If --tls is provided without certificate paths, a self-signed certificate is automatically generated.\n\n"
        "Sample Syntax:\n"
        "  * Download a file via HTTP:\n"
        "      ./file_transfer_tool.py http download --url \"https://example.com/file.txt\" --file \"downloaded.txt\"\n\n"
        "  * Upload a file via SCP:\n"
        "      ./file_transfer_tool.py scp upload --host 192.168.1.100 --username user --password secret --local localfile.txt --remote /remote/path/file.txt\n\n"
        "  * Zip a directory with a manifest:\n"
        "      ./file_transfer_tool.py dir zip --dir \"/path/to/dir\" --output \"archive.zip\" --manifest\n\n"
        "  * Serve a directory over HTTPS (auto-generated self-signed certificate):\n"
        "      ./file_transfer_tool.py dir serve --dir \"/path/to/share\" --host 0.0.0.0 --port 8443 --tls\n\n"
        "  * Serve a directory over HTTPS using your own certificate and key:\n"
        "      ./file_transfer_tool.py dir serve --dir \"/path/to/share\" --host 0.0.0.0 --port 8443 --tls --tls_cert \"/path/to/cert.pem\" --tls_key \"/path/to/key.pem\"\n\n"
        "All operations are intended for authorized testing only."
    )
    parser = argparse.ArgumentParser(
        description=help_text,
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="method", required=True, help="Select the transfer method or directory operation")
    http_parser = subparsers.add_parser("http", help="HTTP/S file transfer (download/upload)")
    http_parser.add_argument("action", choices=["download", "upload"], help="Action: download or upload a file")
    http_parser.add_argument("--url", required=True, help="Target URL (include https:// if needed)")
    http_parser.add_argument("--file", required=True, help="Local file path (destination for download or source for upload)")
    scp_parser = subparsers.add_parser("scp", help="SCP file transfer (requires SSH credentials)")
    scp_parser.add_argument("action", choices=["download", "upload"], help="Action: download from or upload to a remote host")
    scp_parser.add_argument("--host", required=True, help="Remote host IP or domain")
    scp_parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    scp_parser.add_argument("--username", required=True, help="SSH username")
    scp_parser.add_argument("--password", required=True, help="SSH password")
    scp_parser.add_argument("--local", required=True, help="Local file path")
    scp_parser.add_argument("--remote", required=True, help="Remote file path")
    wget_parser = subparsers.add_parser("wget", help="Download a file using wget")
    wget_parser.add_argument("--url", required=True, help="Target URL")
    wget_parser.add_argument("--file", required=True, help="Local file path to save the file")
    curl_parser = subparsers.add_parser("curl", help="Download a file using curl")
    curl_parser.add_argument("--url", required=True, help="Target URL")
    curl_parser.add_argument("--file", required=True, help="Local file path to save the file")
    php_parser = subparsers.add_parser("php", help="Download a file using a PHP one-liner")
    php_parser.add_argument("--url", required=True, help="Target URL")
    php_parser.add_argument("--file", required=True, help="Local file path to save the file")
    dir_parser = subparsers.add_parser("dir", help="Directory operations: zip a directory or serve it via HTTP/HTTPS")
    dir_parser.add_argument("action", choices=["zip", "serve"], help="Action: 'zip' a directory or 'serve' it over HTTP/HTTPS")
    dir_parser.add_argument("--dir", required=True, help="Directory to operate on")
    dir_parser.add_argument("--output", help="Output file path for zipped archive (only for zip action)")
    dir_parser.add_argument("--host", default="0.0.0.0", help="Host to bind the HTTP server (default: 0.0.0.0)")
    dir_parser.add_argument("--port", type=int, default=8000, help="Port for the HTTP server (default: 8000)")
    dir_parser.add_argument("--tls", action="store_true", help="Enable TLS (HTTPS) for serving the directory. If provided without --tls_cert/--tls_key, a self-signed certificate is generated.")
    dir_parser.add_argument("--tls_cert", help="(Optional) Path to TLS certificate file.")
    dir_parser.add_argument("--tls_key", help="(Optional) Path to TLS key file.")
    dir_parser.add_argument("--manifest", action="store_true", help="(For zip action) Generate a manifest file with SHA256 hashes for each file")
    args = parser.parse_args()
    if args.method == "http":
        if args.action == "download":
            http_download(args.url, args.file)
        elif args.action == "upload":
            http_upload(args.url, args.file)
    elif args.method == "scp":
        if args.action == "download":
            scp_download(args.host, args.port, args.username, args.password, args.remote, args.local)
        elif args.action == "upload":
            scp_upload(args.host, args.port, args.username, args.password, args.local, args.remote)
    elif args.method == "wget":
        wget_download(args.url, args.file)
    elif args.method == "curl":
        curl_download(args.url, args.file)
    elif args.method == "php":
        php_download(args.url, args.file)
    elif args.method == "dir":
        if args.action == "zip":
            output_zip = args.output if args.output else os.path.basename(os.path.abspath(args.dir)) + ".zip"
            zip_directory(args.dir, output_zip, generate_manifest=args.manifest)
        elif args.action == "serve":
            serve_directory(args.dir, args.host, args.port, use_tls=args.tls, tls_cert=args.tls_cert, tls_key=args.tls_key)
if __name__ == "__main__":
    main()
