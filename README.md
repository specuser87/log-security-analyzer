# log-security-analyzer
This is a python language based tool that detects suspicious activity in SSH authentication logs
# log-security-analyzer

A Python tool that scans SSH authentication logs and automatically flags suspicious activity — built to practice core Security Operations concepts from CompTIA Security+.

## What it detects

- **Brute force attempts** — flags any IP address with 3 or more failed login attempts
- **Unusual login times** — flags successful logins outside normal business hours (6am–10pm)
- **High-value account targeting** — flags any login attempt (successful or failed) against high-privilege accounts like `root` or `admin`

## Why I built this

Log analysis is one of the core, day-to-day tasks in Security Operations — one of the largest domains covered in the Security+ exam. Rather than just reading about it, I wanted to build something that automates a small piece of that real workflow: spotting patterns in login activity that a human analyst would otherwise have to catch manually.

## How it works

The script reads through a log file line by line and checks each line against three rules:

1. If a line contains a failed login, it extracts the IP address and counts how many times that IP has failed — if it crosses a threshold (3), it's flagged as a possible brute force attempt.
2. If a line contains a successful login, it extracts the timestamp and checks whether the login happened outside normal business hours.
3. Every line is also checked against a list of high-value usernames (`root`, `admin`) — since these accounts are common attacker targets.

## How to run it

1. Make sure Python 3 is installed
2. Place `log_analyzer.py` and `sample_auth.log` in the same folder
3. Run:
