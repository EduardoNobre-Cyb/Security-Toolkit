import re

class LogAnalyzer:
    def __init__(self, log_file_path, threshold=5):
        self.log_file_path = log_file_path
        self.threshold = threshold
        self.failed_attempts = {}

    def parse_log(self):
        try:
            with open(self.log_file_path, "r") as log_file:
                for line in log_file:
                    match = re.search(r'Failed password for (invalid user )?(\w+) from ([\d.]+)', line)
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

        self.suspicious = sorted(self.suspicious, key=lambda x: x[1], reverse=True)

    def report(self):
        print(f"\n=== Analysis Results ===\n")
        print(f"Entries with failed attempts >= {self.threshold}: {len(self.suspicious)}\n")

        if self.suspicious:
            print(f"\n⚠️ SUSPICIOUS ACTIVITY DETECTED (>={self.threshold} failed attempts):\n")
            for (username, ip_address), count in self.suspicious:
                print(f"User: {username}, IP: {ip_address}, Failed Attempts: {count}")
        else:
            print("No suspicious activity detected.")


        print(f"\n=== All Failed Login Attempts ===\n")

        all_sorted = sorted(self.failed_attempts.items(), key=lambda x: x[1], reverse=True)
        for (username, ip_address), count in all_sorted:
            print(f"User: {username}, IP: {ip_address}, Failed Attempts: {count}")

def main():
    print("=== SSH Log Analyzer ===")
    log_file = input("Enter path to SSH auth log file: ")
    threshold_input = input("Enter threshold for failed attempts (default 5): ")
    threshold = int(threshold_input) if threshold_input.isdigit() else 5


    analyzer = LogAnalyzer(log_file, threshold)
    analyzer.parse_log()
    analyzer.analyze()
    analyzer.report()

if __name__ == "__main__":
    main()