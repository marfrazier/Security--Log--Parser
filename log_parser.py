import re
from collections import defaultdict

# Define the file path for our log file
LOG_FILE_PATH = "server_log.txt"

#Security alert thresholds
FAILED_LOGIN_THRESHOLD = 3

def analyze_logs():
    failed_logins = defaultdict(int)
    sql_injection_alerts = ()

    print("=" * 60)
    print("Starting Security Log Analysis...")
    print("=" * 60)

    try:
        with open(LOG_FILE_PATH, 'r') as file:
            for line in file:
                # Clean up white space from the line
                line = line.strip()
                if not line:
                    continue

                # --- DETECT SQL Injection ---
                # Looking for classic patterns like ' OR '1'='1 or similar injection strings

                if "OR '1 = 1" in line or "Union Select" in line.upper():
                    sql_injection_alerts.append(line)

                # --- DETECT BRUTE FORCE ATTACKS --
                # Split the log line by its delimiter " - " to extract components
                # Sample parts: [' 2026 - 05 - 20 14:01:15', '10.0.0.12', 'POST /login', '401 FAILED']
                parts = line.split(" - ")

                if len(parts) == 4:
                    ip_address = parts[1]
                    request_info = parts[2]
                    status = parts[3]

                    #If it's a failed login attempt, increment the counter for that specific IP
                    if "/login" in request_info and "401 FAILED" in status:
                        failed_logins[ip_address] += 1

        # --- REPORTING THE RESULTS ---

        # 1. Flag Brute Force Suspicious Activity
        print("\n[!] Checking for Potential Brute Force Attacks...")
        brute_force_found = False
        for ip, count in failed_logins.items():
            if count >= FAILED_LOGIN_THRESHOLD:
                print(f"ALERT: IP {ip} has {count} failed login attempts!")
                brute_force_found = True
        if not brute_force_found:
            print( "No brute force activity detected.")

        #2. Flag SQL Injection Suspicious Activity
        print("\n[!] Checking for SQL Injection Attempts...")
        if sql_injection_alerts:
            for alert in sql_injection_alerts:
                print(f" ALERT: Suspicious URL payload found:\n --> {alert}")
        else:
            print("No SQL Injection Patterns Detected.")

    except FileNotFoundError:
        print(f"Error: The file '{LOG_FILE_PATH}' was not found. Please check your path.")

    print("\n" + "=" * 60)
    print("Analysis Complete.")
    print("=" * 60)

if __name__ == "__main__":
    analyze_logs()





