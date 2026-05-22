# Python Security Log Parser

A lightweight, local automation script designed to analyze server network logs for potential malicious activity, including Brute-Force attacks and SQL Injection attempts. 

This project demonstrates core concepts in Technical Analysis, Software Quality Assurance (QA) boundary testing, and Cybersecurity monitoring.

## Features

*   **Brute-Force Detection:** Monitors authentication attempts on the /login endpoint. If a single IP address exceeds the configured threshold of failed attempts, a security alert is triggered.
*   **SQL Injection Identification:** Scans incoming request URLs for common SQL injection payloads (such as ' OR '1'='1).
*   **Error Handling:** Utilizes robust try-except blocks to handle missing file paths gracefully without system crashes.
*   **Zero External Dependencies:** Built entirely using Python's standard library modules, ensuring high efficiency and quick deployment.

## How It Works

The script reads a log file line-by-line, splitting the metadata strings into distinct components:
1. Timestamp
2. IP Address
3. HTTP Request Path
4. Status Code

It evaluates each component against defined security rules and tallies metrics using a defaultdict structure.

## How to Run the Project

### Prerequisites
*   Python 3.x installed on your machine.
*   An IDE like PyCharm or a standard terminal utility.

### Setup Instructions
1. Clone or download this repository to your local machine.
2. Ensure both log_parser.py and server_log.txt are sitting in the exact same directory folder.
3. Open the project in PyCharm.
4. Right-click anywhere inside log_parser.py and select Run 'log_parser' (or run python log_parser.py in your terminal).

## Sample Output Results

When executed against the provided mock server_log.txt file, the script outputs the following terminal alerts:

```text
============================================================
STARTING SECURITY LOG ANALYSIS...
============================================================

[!] Checking for Potential Brute Force Attacks...
   ALERT: IP 10.0.0.12 has 5 failed login attempts!

[!] Checking for SQL Injection Attempts...
   ALERT: Suspicious URL payload found:
      --> 2026-05-22 14:05:44 - 192.168.1.75 - GET /search?q=admin' OR '1'='1 - 200 SUCCESS

============================================================
ANALYSIS COMPLETE.
============================================================
