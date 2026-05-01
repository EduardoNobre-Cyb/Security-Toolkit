import re
import requests
import hashlib
import os
import time
import configparser
import argparse
import urllib.parse
import base64
import socket
import threading
import datetime


def load_config():
    config = configparser.ConfigParser()

    # Get directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.ini")

    # Try to read from config.ini
    if os.path.exists(config_path):
        config.read(config_path)
    else:
        # Fall back to environment variables for Docker/container deployment
        # Create default sections
        config.add_section("API_KEYS")
        config.add_section("SETTINGS")

        # Set defaults from environment variables
        virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        threshold = os.getenv("THRESHOLD", "5")

        config.set("API_KEYS", "avScanner", virustotal_key)
        config.set("SETTINGS", "threshold", threshold)

        if not virustotal_key:
            print("WARNING: config.ini not found and VIRUSTOTAL_API_KEY not set")
            print(f"Looking for config.ini at: {config_path}")
            print("Or set VIRUSTOTAL_API_KEY environment variable")

    return config


def parse_args():
    parser = argparse.ArgumentParser(
        description="Security Toolkit - Password Checker, AV Scanner, Log Analyzer - By Eduardo Nob",
        epilog="If no arguments are provided, the interactive menu will be shown.",
    )

    parser.add_argument(
        "--check-password",
        "-p",
        type=str,
        metavar="PASSWORD",
        help="Check if the given password has been leaked",
    )

    parser.add_argument(
        "--scan-file",
        "-sF",
        type=str,
        metavar="FILEPATH",
        help="Scan the given file with VirusTotal",
    )

    parser.add_argument(
        "--analyze-logs",
        "-aL",
        type=str,
        default=None,
        metavar="LOGFILE",
        help="Analyze the given SSH auth log file for failed login attempts",
    )

    parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        metavar="N",
        help="Threshold for suspicious login attempts (default: 5)",
    )

    parser.add_argument(
        "--upload",
        "-u",
        action="store_true",
        help="Upload/submit for scanning (used with --scan-file or --check-url)",
    )

    parser.add_argument(
        "--check-url",
        "-cU",
        type=str,
        metavar="URL",
        help="Check if the given URL is safe using AvScanner",
    )

    parser.add_argument(
        "--scan-ports",
        "-sP",
        type=str,
        metavar="TARGET",
        help="Scan common ports on the given target IP or hostname",
    )

    parser.add_argument(
        "--port-range",
        "-pR",
        type=str,
        metavar="START-END",
        help="Custom port range to scan (used with --scan-ports option), e.g., 20-80",
    )

    parser.add_argument(
        "--save-results",
        "-s",
        action="store_true",
        help="Save port scan results to a file (used with --scan-ports option)",
    )

    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version="Security Toolkit v1.0 - By Eduardo Nob",
        help="Show program version",
    )

    return parser.parse_args()


class PasswordChecker:
    def __init__(self, pwd):
        self.pwd = pwd

    def check_password(self):

        url = "https://api.pwnedpasswords.com/range/"

        hashed = hashlib.sha1(self.pwd.encode("utf-8")).hexdigest().upper()
        prefix, suffix = hashed[:5], hashed[5:]

        response = requests.get(f"{url}{prefix}")

        if suffix in response.text:
            print("Password has been leaked!")
        else:
            print("Password is safe.")


class AvScanner:
    def __init__(self, api_key):
        self.api_key = api_key

    def check_hash(self, file_path):
        # Option 1: Check existing hash

        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found!")
        else:
            print("Calculating file hash...")
            file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            print(f"SHA256: {file_hash}")

            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.api_key}

            print("Checking with VirusTotal...")
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                print(f"\nResults:")
                print(f"Malicious: {stats['malicious']}")
                print(f"Suspicious: {stats['suspicious']}")
                print(f"Undetected: {stats['undetected']}")
                print(f"Harmless: {stats['harmless']}")

                # Filter and display malicious results
                results = data["data"]["attributes"]["last_analysis_results"]
                malicious_results = []
                for engine, result in results.items():
                    if result["category"] == "malicious":
                        malicious_results.append(
                            {"engine": engine, "detection": result["result"]}
                        )

                if malicious_results:
                    print(f"\n⚠️ Detected by {len(malicious_results)} engines:")
                    for item in malicious_results:
                        print(f"  - {item['engine']}: {item['detection']}")

                if stats["malicious"] > 0:
                    print("\n⚠️ WARNING: File flagged as malicious!")
                else:
                    print("\n✓ File appears clean.")
            elif response.status_code == 404:
                print(
                    "File hash not found in VirusTotal database. Try option 2 to upload and scan."
                )
            else:
                print(f"Error: {response.status_code} - {response.text}")

    def upload_and_scan(self, file_path):
        # Option 2: Upload and scan file

        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found!")
        else:
            print("Uploading file to VirusTotal...")
            url = "https://www.virustotal.com/api/v3/files"
            headers = {"x-apikey": self.api_key}

            with open(file_path, "rb") as f:
                files = {"file": f}
                response = requests.post(url, headers=headers, files=files)

            if response.status_code == 200:
                data = response.json()
                analysis_id = data["data"]["id"]
                print(f"\nFile uploaded successfully!")
                print(f"Analysis ID: {analysis_id}")
                print("\nWaiting for analysis to complete...")

                # Poll for results
                analysis_url = (
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                )
                max_attempts = 20  # Wait up to ~40 seconds
                attempt = 0

                while attempt < max_attempts:
                    time.sleep(2)  # Wait 2 seconds between checks
                    result_response = requests.get(analysis_url, headers=headers)

                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        status = result_data["data"]["attributes"]["status"]

                        if status == "completed":
                            # Analysis complete - show results
                            stats = result_data["data"]["attributes"]["stats"]
                            print(f"\n=== Scan Results ===")
                            print(f"Malicious: {stats['malicious']}")
                            print(f"Suspicious: {stats['suspicious']}")
                            print(f"Undetected: {stats['undetected']}")
                            print(f"Harmless: {stats['harmless']}")

                            # Show which engines detected it as malicious
                            results = result_data["data"]["attributes"]["results"]
                            malicious_results = []
                            for engine, result in results.items():
                                if result["category"] == "malicious":
                                    malicious_results.append(
                                        {
                                            "engine": engine,
                                            "detection": result["result"],
                                        }
                                    )

                            if malicious_results:
                                print(
                                    f"\n⚠️ Detected by {len(malicious_results)} engines:"
                                )
                                for item in malicious_results:
                                    print(f"  - {item['engine']}: {item['detection']}")

                            if stats["malicious"] > 0:
                                print("\n⚠️ WARNING: File flagged as malicious!")
                            else:
                                print("\n✓ File appears clean.")
                            break
                        else:
                            print(
                                f"Status: {status}... (attempt {attempt + 1}/{max_attempts})"
                            )
                            attempt += 1
                    else:
                        print(f"Error checking results: {result_response.status_code}")
                        break

                if attempt >= max_attempts:
                    print("\n⏱️ Analysis is taking longer than expected.")
                    print(
                        f"Check results later at: https://www.virustotal.com/gui/file-analysis/{analysis_id}"
                    )
            else:
                print(f"Error: {response.status_code} - {response.text}")


class UrlChecker:
    def __init__(self, api_key):
        self.api_key = api_key

    def check_url(self, url):

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        check_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(check_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            print(f"\nResults for URL: {url}")
            print(f"Malicious: {stats['malicious']}")
            print(f"Suspicious: {stats['suspicious']}")
            print(f"Undetected: {stats['undetected']}")
            print(f"Harmless: {stats['harmless']}")

            # Filter and display malicious results
            results = data["data"]["attributes"]["last_analysis_results"]
            malicious_results = []
            for engine, result in results.items():
                if result["category"] == "malicious":
                    malicious_results.append(
                        {"engine": engine, "detection": result["result"]}
                    )

            if malicious_results:
                print(f"\n⚠️ Detected by {len(malicious_results)} engines:")
                for item in malicious_results:
                    print(f"  - {item['engine']}: {item['detection']}")

            if stats["malicious"] > 0:
                print("\n⚠️ WARNING: File flagged as malicious!")
            else:
                print("\n✓ File appears clean.")

        elif response.status_code == 404:
            print("URL not found in VirusTotal database. Use submit option to scan it.")
        else:
            print(f"Error: {response.status_code} - {response.text}")

    def submit_url(self, url):
        # Submit URL for scanning just like file upload
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        print(f"Submitting URL to VirusTotal: {url}")

        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": self.api_key}
        data = {"url": url}

        response = requests.post(submit_url, headers=headers, data=data)

        if response.status_code == 200:
            result = response.json()
            analysis_id = result["data"]["id"]
            print(f"\nURL submitted successfully!")
            print(f"Analysis ID: {analysis_id}")
            print("\nWaiting for analysis to complete...")

            # Poll for results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            max_attempts = 20
            attempt = 0

            while attempt < max_attempts:
                time.sleep(2)
                result_response = requests.get(analysis_url, headers=headers)

                if result_response.status_code == 200:
                    result_data = result_response.json()
                    status = result_data["data"]["attributes"]["status"]

                    if status == "completed":
                        # Analysis complete - show results
                        stats = result_data["data"]["attributes"]["stats"]
                        print(f"\n=== Scan Results for {url} ===")
                        print(f"Malicious: {stats['malicious']}")
                        print(f"Suspicious: {stats['suspicious']}")
                        print(f"Undetected: {stats['undetected']}")
                        print(f"Harmless: {stats['harmless']}")

                        # Show which engines detected it
                        results = result_data["data"]["attributes"]["results"]
                        malicious_results = []
                        for engine, result in results.items():
                            if result["category"] == "malicious":
                                malicious_results.append(
                                    {
                                        "engine": engine,
                                        "detection": result.get("result", "Malicious"),
                                    }
                                )

                        if malicious_results:
                            print(f"\n⚠️ Detected by {len(malicious_results)} engines:")
                            for item in malicious_results:
                                print(f"  - {item['engine']}: {item['detection']}")

                        if stats["malicious"] > 0:
                            print("\n⚠️ WARNING: URL flagged as malicious!")
                        else:
                            print("\n✓ URL appears clean.")
                        break
                    else:
                        print(
                            f"Status: {status}... (attempt {attempt + 1}/{max_attempts})"
                        )
                        attempt += 1
                else:
                    print(f"Error checking results: {result_response.status_code}")
                    break

            if attempt >= max_attempts:
                print("\n⏱️ Analysis is taking longer than expected.")
                print(
                    f"Check results later at: https://www.virustotal.com/gui/url/{analysis_id}"
                )
        else:
            print(f"Error: {response.status_code} - {response.text}")


class LogAnalyzer:
    def __init__(self, log_file_path, threshold=5):
        self.log_file_path = log_file_path
        self.threshold = threshold
        self.failed_attempts = {}
        self.location_cache = {}
        self.high_risk_countries = {
            "North Korea",
            "Iran",
            "Syria",
            "Russia",
            "China",
            "Pakistan",
            "Afghanistan",
            "Belarus",
            "Venezuela",
        }

    def parse_log(self):
        try:
            with open(self.log_file_path, "r") as log_file:
                for line in log_file:
                    match = re.search(
                        r"Failed password for (invalid user )?(\w+) from ([\d.]+)", line
                    )
                    if match:
                        username = match.group(2)
                        ip_address = match.group(3)
                        key = (username, ip_address)
                        if key not in self.failed_attempts:
                            self.failed_attempts[key] = 0
                        self.failed_attempts[key] += 1
        except FileNotFoundError:
            print(f"Error: Could not find {self.log_file_path}")
            exit()
        except Exception as e:
            print(f"Error reading file: {e}")
            exit()

    def analyze(self):
        self.suspicious = []
        for key, count in self.failed_attempts.items():
            if count >= self.threshold:
                self.suspicious.append((key, count))

        # Sort by: 1) High-risk First, 2) Count (highest first)

        self.suspicious = sorted(
            self.suspicious,
            key=lambda x: (
                self.is_high_risk(self.get_location(x[0][1])["country"]),
                x[1],
            ),
            reverse=True,
        )

    def report(self):
        print(f"\n=== Analysis Results ===\n")
        print(
            f"Entries with failed attempts >= {self.threshold}: {len(self.suspicious)}\n"
        )

        if self.suspicious:
            print(
                f"\n⚠️ SUSPICIOUS ACTIVITY DETECTED (>={self.threshold} failed attempts):\n"
            )
            for (username, ip_address), count in self.suspicious:
                location = self.get_location(ip_address)
                risk_flag = (
                    "🚩 [HIGH RISK] - "
                    if self.is_high_risk(location["country"])
                    else ""
                )
                print(
                    f"  🚨 {risk_flag}User: {username}, IP: {ip_address}, "
                    f"Location: {location['city']}, {location['country']}, "
                    f"Failed Attempts: {count}"
                )
        else:
            print("No suspicious activity detected.")

        print(f"\n=== All Failed Login Attempts ===\n")

        all_sorted = sorted(
            self.failed_attempts.items(),
            key=lambda x: (
                self.is_high_risk(self.get_location(x[0][1])["country"]),
                x[1],
            ),
            reverse=True,
        )

        for (username, ip_address), count in all_sorted:
            location = self.get_location(ip_address)
            risk_flag = "🚩 " if self.is_high_risk(location["country"]) else ""
            print(
                f"  {risk_flag}User: {username}, IP: {ip_address}, "
                f"Location: {location['city']}, {location['country']}, "
                f"Failed Attempts: {count}"
            )

    def get_location(self, ip_address):

        if ip_address in self.location_cache:
            return self.location_cache[ip_address]

        # API Rate limiting: 1 request per 1.4 seconds given 45 requests/min limit
        time.sleep(1.4)

        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data["status"] == "success":
                    location = {
                        "country": data["country"],
                        "city": data.get("city", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                    }
                    self.location_cache[ip_address] = location
                    return location
        except:
            pass

        default = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
        self.location_cache[ip_address] = default
        return default

    def is_high_risk(self, country):
        # Check if country is in high-risk list
        return country in self.high_risk_countries


class PortScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
        self.lock = threading.Lock()  # Prevents threading conflicts

        # Dictionary of common ports and their services
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "Alt-HTTPS",
        }

    def scan_port(self, port, timeout=1):
        try:
            # Create socket (network connection)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Timeout after 1 second
            sock.settimeout(timeout)
            # Try to connect to the port (return 0 if successful)
            result = sock.connect_ex((self.target, port))
            sock.close()

            # If connection successful, port is open
            if result == 0:
                service = self.common_ports.get(port, "Unknown")

                # Use Lock to safely add to list (prevents thread collision)
                with self.lock:
                    self.open_ports.append((port, service))
                    print(f"✓ Port {port} is OPEN - {service}")

        except socket.gaierror:
            # DNS lookup failed - invalid hostname
            print(f"Error: Could not resolve hostname {self.target}")
        except socket.error:
            # Other network error
            pass

    def scan(self, custom_ports=None, save_to_file=False):
        print(f"\n🔍 Scanning {self.target}...")
        print("=" * 60)

        # Use custom ports if provided, else use common ports
        ports_to_scan = custom_ports if custom_ports else self.common_ports.keys()

        threads = []

        # Create one thread per port to scan
        for port in ports_to_scan:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()  # Launch the thread (runs in background)

        for thread in threads:
            thread.join()  # Wait for all threads to finish

        # Display summary of open ports
        self._display_results(save_to_file)

    def _display_results(self, save_to_file):
        # Summary of open ports
        print("\n=== Scan Complete ===")
        print("\n" + "=" * 60)
        if self.open_ports:
            # Sort by port number
            self.open_ports.sort(key=lambda x: x[0])

            print(f"🚨 Found {len(self.open_ports)} open port(s):")
            for port, service in self.open_ports:
                print(f"  → Port {port}: {service}")

            if save_to_file:
                self._save_results()

        else:
            print("✓ No open ports found (or host is down)")

        print("=" * 60)

    def _save_results(self):
        # Create filename with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"portscan_{self.target}_{timestamp}.txt"

        try:
            with open(filename, "w") as f:
                f.write(f"Port Scan Results for {self.target}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")

                if self.open_ports:
                    f.write(f"Open Ports Found: {len(self.open_ports)}\n\n")
                    for port, service in self.open_ports:
                        f.write(f"Port {port}: {service}\n")
                else:
                    f.write("No open ports found.\n")

            print(f"\n💾 Results saved to: {filename}")
        except Exception as e:
            print(f"\n⚠️ Error saving file: {e}")


def menu(config):
    # Run interactive meny mode
    avS_api_key = config["API_KEYS"]["avScanner"]
    default_threshold = int(config["SETTINGS"]["threshold"])

    while True:
        print(
            """
        ╔═══════════════════════════════╗
        ║   SECURITY TOOLKIT v1.0       ║
        ║   Created by Eduardo Nob      ║
        ╚═══════════════════════════════╝
        """
        )
        print("1. Check Password (Pwned)")
        print("2. Scan File with VirusTotal")
        print("3. Analyze SSH Logs")
        print("4. URL Safety Check")
        print("5. Port Scanner")
        print("6. Exit")

        choice = input("Select tool: ")

        if choice == "1":
            # Run password checker logic
            print("=== Password Leak Checker ===")
            pwd = input("Enter password to check: ")
            checker = PasswordChecker(pwd)
            checker.check_password()

        elif choice == "2":
            # Run AV scanner logic
            print("=== VirusTotal File Checker ===")
            print("1. Check file hash (faster, more private)")
            print("2. Upload and scan file (for new/unknown files)")
            choice = input("Choose option (1/2): ")

            if choice == "1":
                # Check file hash logic
                file_path = input("Enter file path: ")
                # api_key = input("Enter your VirusTotal API key: ")
                scanner = AvScanner(avS_api_key)
                scanner.check_hash(file_path)

            if choice == "2":
                # Upload and scan file logic would go here
                file_path = input("Enter file path: ")
                # api_key = input("Enter your VirusTotal API key: ")
                scanner = AvScanner(avS_api_key)
                scanner.upload_and_scan(file_path)

        elif choice == "3":
            print("=== SSH Log Analyzer ===")
            log_file = input("Enter path to SSH auth log file: ")
            threshold_input = input(
                f"Enter threshold for failed attempts (default {default_threshold}): "
            )
            threshold = (
                int(threshold_input) if threshold_input.isdigit() else default_threshold
            )

            analyzer = LogAnalyzer(log_file, threshold)
            analyzer.parse_log()
            analyzer.analyze()
            analyzer.report()

        elif choice == "4":
            print("=== URL Safety Checker ===")
            print("1. Check URL (lookup existing scan)")
            print("2. Submit URL for scanning (new analysis)")
            url_choice = input("Choose option (1/2): ")

            url = input("Enter URL to check: ")
            url_checker = UrlChecker(avS_api_key)

            if url_choice == "2":
                url_checker.submit_url(url)
            else:
                url_checker.check_url(url)

        elif choice == "5":
            print("=== Port Scanner ===")
            target = input("Enter target IP or hostname: ")

            print("1. Scan common ports (fast)")
            print("2. Scan custom ports range")
            port_choice = input("Choose option (1/2): ")

            # Ask about saving to file
            save_input = input("Save results to file? (y/n): ").lower()
            save_to_file = save_input == "y"

            scanner = PortScanner(target)

            if port_choice == "2":
                start = int(input("Enter start port: "))
                end = int(input("Enter end port: "))
                custom_ports = range(start, end + 1)
                scanner.scan(custom_ports, save_to_file)

            else:
                scanner.scan(save_to_file=save_to_file)

        elif choice == "6":
            print("Exiting Security Toolkit...")
            break


def cli_main(args, config):
    avS_api_key = config["API_KEYS"]["avScanner"]
    default_threshold = int(config["SETTINGS"]["threshold"])

    # Check Password
    if args.check_password:
        print("=== Password Leak Checker ===")
        checker = PasswordChecker(args.check_password)
        checker.check_password()
        return

    # Scan Files with Av Scanner
    if args.scan_file:
        print("=== VirusTotal File Checker ===")
        scanner = AvScanner(avS_api_key)
        if args.upload:
            scanner.upload_and_scan(args.scan_file)
        else:
            scanner.check_hash(args.scan_file)
        return

    # Analyze SSH Logs
    if args.analyze_logs:
        print("=== SSH Log Analyzer ===")
        threshold = args.threshold if args.threshold is not None else default_threshold
        analyzer = LogAnalyzer(args.analyze_logs, threshold)
        analyzer.parse_log()
        analyzer.analyze()
        analyzer.report()
        return

    # Check URL Safety
    if args.check_url:
        print("=== URL Safety Checker ===")
        url_checker = UrlChecker(avS_api_key)
        if args.upload:
            url_checker.submit_url(args.check_url)
        else:
            url_checker.check_url(args.check_url)
        return

    # Scans Ports
    if args.scan_ports:
        print("=== Port Scanner ===")
        scanner = PortScanner(args.scan_ports)

        if args.port_range:
            try:
                start, end = map(int, args.port_range.split("-"))
                custom_ports = range(start, end + 1)
                scanner.scan(custom_ports, save_to_file=args.save_results)
            except ValueError:
                print("Error: Invalid port range format. Use START-END (e.g., 20-80).")
        else:
            scanner.scan(save_to_file=args.save_results)
        return


def main():
    # Load Configuration
    config = load_config()

    # Parse CLI Arguments
    args = parse_args()

    # Check if any CLI arguments were provided
    if (
        args.check_password
        or args.scan_file
        or args.analyze_logs
        or args.check_url
        or args.scan_ports
    ):
        # CLI mode - run specified tool and exit
        cli_main(args, config)
    else:
        # Interactive mode - show menu
        menu(config)


if __name__ == "__main__":
    main()
