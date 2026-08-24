from datetime import datetime

failed_attempts = {}
unusual_logins = []

# define "business hours" as 6am to 10pm - outside this is flagged
NORMAL_START_HOUR = 6
NORMAL_END_HOUR = 22

with open("sample_auth.log", "r") as file:
    for line in file:
        line = line.strip()

        # --- track failed login attempts per IP ---
        if "Failed password" in line:
            parts = line.split("from ")
            ip = parts[1].split(" port")[0]
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        # --- check for successful logins at unusual hours ---
        if "Accepted password" in line:
            # extract the timestamp - it's the first part of the line
            timestamp_str = line.split(" sshd")[0]
            login_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            if login_time.hour < NORMAL_START_HOUR or login_time.hour >= NORMAL_END_HOUR:
                unusual_logins.append((line, login_time.hour))

print("=== Suspicious IPs (3+ failed logins) ===")
for ip, count in failed_attempts.items():
    if count >= 3:
        print(f"ALERT: {ip} had {count} failed login attempts")

print("\n=== Successful Logins at Unusual Hours ===")
for line, hour in unusual_logins:
    print(f"ALERT: Login at {hour}:00 - {line}")