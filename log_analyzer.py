from datetime import datetime

# Settings: change these to tune what gets flagged.
LOG_FILE = "sample_auth.log"
NORMAL_START_HOUR = 6          # logins before 6am are unusual
NORMAL_END_HOUR = 22           # logins from 10pm onwards are unusual
FAILED_THRESHOLD = 3           # this many failed logins from one IP is flagged
PRIVILEGED_ACCOUNTS = ("root", "admin")


def get_ip(line):
    # The IP address sits between "from " and " port".
    return line.split("from ")[1].split(" port")[0]


def get_user(line):
    # The username sits between " for " and " from".
    return line.split(" for ")[1].split(" from")[0]


def get_time(line):
    # The timestamp is the first part of the line, before " sshd".
    return datetime.strptime(line.split(" sshd")[0], "%Y-%m-%d %H:%M:%S")


def detect(lines):
    # Detection only: read the lines and collect what looks suspicious.
    failed_by_ip = {}
    failed_privileged = {}
    unusual_logins = []

    for line in lines:
        if "Failed password" in line:
            ip = get_ip(line)
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

            user = get_user(line)
            if user in PRIVILEGED_ACCOUNTS:
                failed_privileged[user] = failed_privileged.get(user, 0) + 1

        if "Accepted password" in line:
            hour = get_time(line).hour
            if hour < NORMAL_START_HOUR or hour >= NORMAL_END_HOUR:
                unusual_logins.append((line, hour))

    return failed_by_ip, failed_privileged, unusual_logins


def report(failed_by_ip, failed_privileged, unusual_logins):
    # Reporting only: print the findings. Detection rules are not touched here.
    print("=== Suspicious IPs (%d+ failed logins) ===" % FAILED_THRESHOLD)
    for ip, count in failed_by_ip.items():
        if count >= FAILED_THRESHOLD:
            print(f"ALERT: {ip} had {count} failed login attempts")

    print("\n=== Failed Logins on Privileged Accounts ===")
    for user, count in failed_privileged.items():
        print(f"ALERT: {count} failed login attempts on the {user} account")

    print("\n=== Successful Logins at Unusual Hours ===")
    for line, hour in unusual_logins:
        print(f"ALERT: Login at {hour}:00 - {line}")


def main():
    with open(LOG_FILE, "r") as file:
        lines = [line.strip() for line in file]
    failed_by_ip, failed_privileged, unusual_logins = detect(lines)
    report(failed_by_ip, failed_privileged, unusual_logins)


main()