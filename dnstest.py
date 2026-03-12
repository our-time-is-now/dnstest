#!/usr/bin/env python3
import subprocess
import os
import sys
import time
from datetime import datetime
import signal
import threading
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Global variables
successful_ips = []
failed_ips = []
# Thread locks
print_lock = threading.Lock()
list_lock = threading.Lock()
file_lock = threading.Lock()
port_lock = threading.Lock()

# Port range for dynamic port allocation
PORT_START = 2083
PORT_END = 2100
port_counter = PORT_START

# Default output file
SUCCESS_FILE = f'successful_resolvers-{datetime.now().strftime("%Y_%M_%d-%H_%M_%S")}.txt'


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='DNS tunnel testing tool with multiple scan methods',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com -l dns_list.txt -m full
  %(prog)s -d example.com -l dns_list.txt -m edns -w 20
  %(prog)s -d example.com -l dns_list.txt -m resolve-only -k custom.pem
  %(prog)s -d example.com -l dns_list.txt -m tunnel-only -p 2083-2200
  %(prog)s -d example.com -l dns_list.txt -m tunnel-only -p 2083-2200 -r 2
        """
    )

    parser.add_argument('-d', '--domain',
                        required=True,
                        help='Domain name for DNS resolution (e.g., example.com)')

    parser.add_argument('-l', '--list',
                        required=True,
                        help='Path to file containing DNS resolver IPs (one per line)')

    parser.add_argument('-k', '--pubkey',
                        default='key.pem',
                        help='Path to public key file for dnstt (default: pub.pem)')

    parser.add_argument('-w', '--workers',
                        type=int,
                        default=10,
                        help='Number of concurrent workers (default: 10)')

    parser.add_argument('-m', '--method',
                        choices=['full', 'edns',
                                 'resolve-only', 'tunnel-only'],
                        default='full',
                        help='''
Scan method:
  full         : Complete test (DNS resolution + EDNS + tunnel)
  edns         : DNS resolution + EDNS test only (no tunnel)
  resolve-only : DNS resolution test only
  tunnel-only  : Tunnel test only (skip DNS resolution check)
                       ''')
    parser.add_argument('-r', '--round',
                        type=int,
                        default=1,
                        help='How many time tunnel test runs for every resolver')

    parser.add_argument('-p', '--port-range',
                        default='2083-2100',
                        help='Port range for tunnel clients (format: START-END, default: 2083-2100)')

    parser.add_argument('-o', '--output',
                        default=SUCCESS_FILE,
                        help='Output file for successful resolvers (default: successful_resolvers.txt)')

    parser.add_argument('--no-clear',
                        action='store_true',
                        help='Disable screen clearing between tests')

    return parser.parse_args()


def parse_port_range(port_range_str):
    """Parse port range string (e.g., '2083-2100') into (start, end)."""
    try:
        start, end = map(int, port_range_str.split('-'))
        if start >= end:
            raise ValueError("Start port must be less than end port")
        if start < 1024 or end > 65535:
            raise ValueError("Ports must be between 1024 and 65535")
        return start, end
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port range: {e}")


def clear_screen():
    """Clears the terminal screen."""
    if sys.platform == 'win32':
        os.system('cls')  # For Windows
    else:
        os.system('clear')  # For Linux/macOS


def safe_print(message):
    """Thread-safe printing."""
    with print_lock:
        print(message)


def write_success_to_file(dns_ip, method, edns_size=None, port=None):
    """Write a successful DNS resolver to file immediately."""
    try:
        with file_lock:
            with open(SUCCESS_FILE, 'a') as f:
                edns_info = f" | EDNS:{edns_size}" if edns_size else ""
                f.write(f"{dns_ip} | METHOD:{method}{edns_info}\n")
                f.flush()
                os.fsync(f.fileno())
    except Exception as e:
        safe_print(f"⚠️  Error writing to success file: {e}")


def initialize_success_file(method):
    """Initialize the success file with a header."""
    try:
        with file_lock:
            with open(SUCCESS_FILE, 'w') as f:
                f.write(
                    f"# Successful DNS Resolvers - Scan Method: {method}\n")
                f.write(
                    "# Format: IP_Address | METHOD:method | EDNS:size\n")
                f.write("# " + "="*70 + "\n")
                f.flush()
    except Exception as e:
        safe_print(f"⚠️  Error initializing success file: {e}")


def get_next_port():
    """Get the next available port in a thread-safe manner."""
    global port_counter, PORT_START, PORT_END
    with port_lock:
        port = port_counter
        port_counter += 1
        if port_counter > PORT_END:
            port_counter = PORT_START
        return port


def is_port_available(port):
    """Check if a port is available."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('127.0.0.1', port))
            return True
        except socket.error:
            return False


def find_available_port(start_port):
    """Find an available port starting from start_port."""
    global PORT_END
    port = start_port
    while port <= PORT_END:
        if is_port_available(port):
            return port
        port += 1
    # If no ports available in range, try random ports
    for _ in range(10):
        test_port = 3000 + hash(str(time.time())) % 10000
        if is_port_available(test_port):
            return test_port
    raise RuntimeError("No available ports found")


def test_dns_resolution(dns_ip, domain):
    """Test if the DNS resolver can resolve the NS record for the domain."""
    try:
        dig_command = [
            "dig", f"@{dns_ip}", "NS", domain, "+short", "+time=5", "+tries=1"
        ]

        result = subprocess.run(
            dig_command, capture_output=True, text=True, timeout=10)

        if result.stdout.strip():
            safe_print(f"✅ DNS resolver {
                       dns_ip} resolved NS records for {domain}")
            return True
        else:
            safe_print(f"❌ DNS resolver {
                       dns_ip} failed to resolve NS records for {domain}")
            return False

    except subprocess.TimeoutExpired:
        safe_print(f"⏱️  DNS resolver {dns_ip} timed out")
        return False
    except Exception as e:
        safe_print(f"⚠️  Error testing DNS resolver {dns_ip}: {e}")
        return False


def test_edns_payload_size(dns_ip, domain):
    """Test EDNS payload size support and find maximum supported size."""
    try:
        payload_sizes = [512, 1232, 1432, 4096]
        max_supported = 512

        safe_print(f"📦 Testing EDNS payload size for {dns_ip}...")

        for size in payload_sizes:
            dig_command = [
                "dig", f"@{dns_ip}", "NS", domain,
                "+bufsize=" + str(size),
                "+dnssec",
                "+time=3",
                "+tries=1",
                "+ignore"
            ]

            result = subprocess.run(
                dig_command, capture_output=True, text=True, timeout=8)

            if "truncated" not in result.stderr.lower() and "bad packet" not in result.stderr.lower():
                max_supported = size
                safe_print(f"  ✓ EDNS payload size {size} supported")
            else:
                safe_print(f"  ✗ EDNS payload size {size} failed")
                break

        safe_print(f"  📊 Max supported EDNS payload size for {
                   dns_ip}: {max_supported}")

        return max_supported

    except subprocess.TimeoutExpired:
        safe_print(f"⏱️  EDNS test timed out for {dns_ip}")
        return 0
    except Exception as e:
        safe_print(f"⚠️  Error testing EDNS for {dns_ip}: {e}")
        return 0


def test_tunnel_connection(dns_ip, domain, pubkey_path, local_port, round):
    """Test dnstt tunnel connection."""
    process = None
    final_result = False,'000%'
    for i in range(round):
        try:
            dnstt_command = [
                "./dnstt-client-linux-amd64",
                "-udp", f'{dns_ip}:53',
                "-pubkey-file", pubkey_path,
                "-utls", "Chrome_120",
                domain,
                f"127.0.0.1:{local_port}"
            ]

            safe_print(f"🔄 Starting DNS tunnel client with DNS server: {dns_ip} on port {local_port}")
            process = subprocess.Popen(
                dnstt_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)

            curl_command = [
                "curl", "--socks5", f"127.0.0.1:{local_port}",
                "--max-time", "10",
                "--silent", "--output", "/dev/null",
                "--write-out", "%{http_code}",
                "https://www.gstatic.com/generate_204"
            ]

            result = subprocess.run(
                curl_command, capture_output=True, text=True, timeout=15)
            http_code = result.stdout.strip()

            final_result =  http_code == "204", http_code

        except subprocess.TimeoutExpired:
            safe_print(f"⏱️  Tunnel test timed out for {dns_ip}")
            return False, "Timeout"
        except Exception as e:
            safe_print(f"⚠️  Error in tunnel test for {dns_ip}: {e}")
            return False, str(e)
        finally:
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except:
                    process.kill()
    return final_result


def test_resolver(args, dns_ip):
    """Test a single DNS resolver based on selected method."""
    local_port = None
    success = False
    edns_size = None

    try:
        # DNS Resolution Test (skip for tunnel-only method)
        if args.method != 'tunnel-only':
            if not test_dns_resolution(dns_ip, args.domain):
                with list_lock:
                    failed_ips.append(f"{dns_ip} (DNS resolution failed)")
                return False, dns_ip, "DNS resolution failed"
        else:
            safe_print(f"ℹ️  Skipping DNS resolution check for {
                       dns_ip} (tunnel-only mode)")

        # If resolve-only, mark as successful
        if args.method == 'resolve-only':
            safe_print(f"✅ SUCCESS: DNS {dns_ip} - Resolution successful")
            with list_lock:
                successful_ips.append(f"{dns_ip} (DNS resolution)")
            write_success_to_file(dns_ip, 'resolve-only')
            return True, dns_ip, "Resolution success"

        # EDNS Test (for full, edns methods)
        if args.method in ['full', 'edns']:
            edns_size = test_edns_payload_size(dns_ip, args.domain)

            if args.method == 'edns':
                # For edns method, success means EDNS >= 1232
                if edns_size >= 1232:
                    safe_print(f"✅ SUCCESS: DNS {
                               dns_ip} - EDNS size {edns_size} sufficient")
                    with list_lock:
                        successful_ips.append(f"{dns_ip} (EDNS:{edns_size})")
                    write_success_to_file(dns_ip, 'edns', edns_size)
                    return True, dns_ip, f"EDNS success ({edns_size})"
                else:
                    safe_print(f"❌ FAILED: DNS {
                               dns_ip} - EDNS size {edns_size} insufficient")
                    with list_lock:
                        failed_ips.append(
                            f"{dns_ip} (EDNS:{edns_size} insufficient)")
                    return False, dns_ip, f"EDNS insufficient ({edns_size})"

        # Tunnel Test (for full, tunnel-only methods)
        if args.method in ['full', 'tunnel-only']:
            if not os.path.exists(args.pubkey):
                print(f"Error: Public key file '{args.pubkey}' not found.")
                sys.exit(1)
            # Get a unique port for tunnel
            local_port = find_available_port(get_next_port())
            safe_print(f"🔌 Assigned port {local_port} for DNS {dns_ip}")

            # Test tunnel connection
            tunnel_success, http_code = test_tunnel_connection(dns_ip, args.domain, args.pubkey, local_port, args.round)

            if tunnel_success:
                success_msg = f"HTTP {http_code}"
                if args.method == 'full' and edns_size:
                    safe_print(f"✅ SUCCESS: DNS {
                               dns_ip} - {success_msg} - EDNS:{edns_size} - PORT:{local_port}")
                    with list_lock:
                        successful_ips.append(
                            f"{dns_ip} (EDNS:{edns_size}, PORT:{local_port})")
                    write_success_to_file(
                        dns_ip, 'full', edns_size, local_port)
                else:
                    safe_print(f"✅ SUCCESS: DNS {
                               dns_ip} - {success_msg} - PORT:{local_port}")
                    with list_lock:
                        successful_ips.append(f"{dns_ip} (PORT:{local_port})")
                    write_success_to_file(
                        dns_ip, 'tunnel-only', port=local_port)
                return True, dns_ip, success_msg
            else:
                safe_print(f"❌ FAILED: DNS {
                           dns_ip} - Tunnel test failed ({http_code})")
                with list_lock:
                    failed_ips.append(f"{dns_ip} (Tunnel failed: {
                                      http_code}, PORT:{local_port})")
                return False, dns_ip, f"Tunnel failed ({http_code})"

        return False, dns_ip, "Unknown method"

    except Exception as e:
        safe_print(f"⚠️  ERROR: DNS {dns_ip} - {str(e)}")
        with list_lock:
            failed_ips.append(f"{dns_ip} (Error: {str(e)[:30]})")
        return False, dns_ip, str(e)
    finally:
        time.sleep(0.5)


def display_results(method):
    """Display the final results."""
    print("\n" + "="*70)
    print(f"FINAL RESULTS - Method: {method}")
    print("="*70)

    print(f"\n✅ SUCCESSFUL RESOLVERS ({len(successful_ips)}):")
    if successful_ips:
        for i, entry in enumerate(successful_ips, 1):
            print(f"    {i:2}. ✓ {entry}")
        print(f"\n  💾 Results saved to: {SUCCESS_FILE}")
    else:
        print("  None")

    print(f"\n❌ FAILED RESOLVERS ({len(failed_ips)}):")
    if failed_ips:
        for i, entry in enumerate(failed_ips[:20], 1):
            print(f"    {i:2}. ✗ {entry}")
        if len(failed_ips) > 20:
            print(f"    ... and {len(failed_ips) - 20} more")
    else:
        print("  None")

    print("\n" + "="*70)


def main():
    """Main function."""
    global PORT_START, PORT_END, SUCCESS_FILE, port_counter

    # Parse arguments
    args = parse_arguments()

    # Set global variables from arguments
    PORT_START, PORT_END = parse_port_range(args.port_range)
    port_counter = PORT_START
    SUCCESS_FILE = args.output

    # Read DNS list
    if not os.path.exists(args.list):
        print(f"Error: DNS list file '{args.list}' does not exist.")
        sys.exit(1)

    with open(args.list, 'r') as f:
        dns_ips = [line.strip() for line in f if line.strip()]

    # Check public key file for methods that need it
    if args.method in ['full', 'tunnel-only']:
        if not os.path.exists(args.pubkey):
            print(f"Error: Public key file '{args.pubkey}' not found.")
            sys.exit(1)

    # Validate port availability for methods that use tunnels
    if args.method in ['full', 'tunnel-only']:
        available_ports = PORT_END - PORT_START + 1
        if args.workers > available_ports:
            print(f"⚠️  Warning: {args.workers} workers but only {
                  available_ports} ports available")
            print(f"   Adjusting workers to {available_ports}")
            args.workers = available_ports

    # Initialize output file
    initialize_success_file(args.method)

    # Display configuration
    print("\n" + "="*70)
    print("DNS TUNNEL TESTER CONFIGURATION")
    print("="*70)
    print(f"📋 Domain:          {args.domain}")
    print(f"📋 DNS List:        {args.list} ({len(dns_ips)} resolvers)")
    print(f"🔑 Public Key:      {args.pubkey}")
    print(f"⚙️  Scan Method:     {args.method}")
    print(f"⚙️  Workers:         {args.workers}")

    if args.method in ['full', 'tunnel-only']:
        print(f"🔌 Port Range:      {PORT_START}-{PORT_END} ({PORT_END - PORT_START + 1} ports)")

    print(f"💾 Output File:     {SUCCESS_FILE}")
    print("="*70 + "\n")

    if not args.no_clear:
        clear_screen()

    # Run tests
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {
            executor.submit(test_resolver, args, dns_ip): dns_ip
            for dns_ip in dns_ips
        }

        completed = 0
        total = len(dns_ips)

        for future in as_completed(future_to_ip):
            completed += 1
            try:
                future.result()
            except Exception as e:
                safe_print(f"⚠️  Unexpected error: {e}")

            if completed % 10 == 0:
                safe_print(f"📊 Progress: {completed}/{total} tests completed")

    # Display results
    display_results(args.method)

    # Final message
    if successful_ips:
        print(f"\n📁 {len(successful_ips)} successful resolvers saved to: {SUCCESS_FILE}")
        print(f"   View with: cat {SUCCESS_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        display_results("interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n⚠️  Fatal error: {e}")
        sys.exit(1)
        print(f"\n⚠️  Fatal error: {e}")
        sys.exit(1)
