import re

log_file_path = "auth_sample.log"

threshold = 5

failed_attempts = {}

try:
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = re.search(r'Failed password for (invalid user )?(\w+) from ([\d.]+)', line)
            if match:
                username = match.group(2)
                ip_address = match.group(3)
                key = (username, ip_address)
                if key not in failed_attempts:
                    failed_attempts[key] = 0
                failed_attempts[key] += 1
except FileNotFoundError:
    print(f"Error: Could not find {log_file_path}")
    exit()
except Exception as e:
    print(f"Error reading file: {e}")
    exit()

total_entries = len(failed_attempts)

suspicious = []
for key, count in failed_attempts.items():
    if count >= threshold:
        suspicious.append((key, count))

suspicious = sorted(suspicious, key=lambda x: x[1], reverse=True)

print(f"\n=== Analysis Results ===\n")
print(f"Total unique username/IP combinations: {total_entries}")
print(f"Entries with failed attempts >= {threshold}: {len(suspicious)}\n")

if suspicious:
    print(f"\n⚠️ SUSPICIOUS ACTIVITY DETECTED (>={threshold} failed attempts):\n")
    for (username, ip_address), count in suspicious:
        print(f"User: {username}, IP: {ip_address}, Failed Attempts: {count}")
else:
    print("No suspicious activity detected.")


print(f"\n=== All Failed Login Attempts ===\n")

all_sorted = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)
for (username, ip_address), count in all_sorted:
    print(f"User: {username}, IP: {ip_address}, Failed Attempts: {count}")