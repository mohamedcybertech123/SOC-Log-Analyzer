# ==========================================
# SOC LOG ANALYZER
# ==========================================

print("=" * 55)
print("              SOC LOG ANALYZER")
print("=" * 55)


# ==========================================
# LOAD SECURITY LOGS
# ==========================================

with open("sample_logs.txt", "r") as file:
    logs = file.readlines()

print("\nSecurity logs loaded successfully!")


# ==========================================
# VARIABLES
# ==========================================

total_events = 0
successful_logins = 0
failed_logins = 0

failed_by_ip = {}
target_accounts = {}

# Tracks failures that happened before a success
current_failures = {}

# Stores suspicious successful logins
suspicious_successes = []


# ==========================================
# ANALYZE LOGS
# ==========================================

print("\nSECURITY EVENTS")
print("-" * 55)

for log in logs:

    log = log.strip()

    if not log:
        continue

    total_events += 1

    print(log)

    parts = log.split()

    username = parts[-2].replace("user=", "")
    ip_address = parts[-1].replace("ip=", "")


    # --------------------------------------
    # FAILED LOGIN
    # --------------------------------------

    if "LOGIN_FAILED" in log:

        failed_logins += 1

        if ip_address in failed_by_ip:
            failed_by_ip[ip_address] += 1
        else:
            failed_by_ip[ip_address] = 1

        target_accounts[ip_address] = username


        # Track current failures
        if ip_address in current_failures:
            current_failures[ip_address] += 1
        else:
            current_failures[ip_address] = 1


    # --------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------

    elif "LOGIN_SUCCESS" in log:

        successful_logins += 1

        previous_failures = current_failures.get(
            ip_address,
            0
        )

        # Suspicious if success happens
        # after 5 or more failures
        if previous_failures >= 5:

            suspicious_successes.append({
                "ip": ip_address,
                "user": username,
                "failures": previous_failures
            })

        # Reset consecutive failures after success
        current_failures[ip_address] = 0


# ==========================================
# LOGIN SUMMARY
# ==========================================

print("\n" + "=" * 55)
print("LOGIN SUMMARY")
print("=" * 55)

print("Total Events:", total_events)
print("Successful Logins:", successful_logins)
print("Failed Logins:", failed_logins)


# ==========================================
# FAILED LOGINS BY IP
# ==========================================

print("\nFAILED LOGINS BY IP")
print("-" * 55)

if failed_by_ip:

    for ip, attempts in failed_by_ip.items():

        print(
            ip,
            "->",
            attempts,
            "failed attempts"
        )

else:

    print("No failed login activity detected.")


# ==========================================
# SECURITY ALERTS
# ==========================================

print("\n" + "=" * 55)
print("SECURITY ALERTS")
print("=" * 55)

total_alerts = 0

critical_alerts = 0
high_alerts = 0
medium_alerts = 0
low_alerts = 0


# ------------------------------------------
# FAILED LOGIN ALERTS
# ------------------------------------------

for ip, attempts in failed_by_ip.items():

    account = target_accounts[ip]

    if attempts >= 10:

        print("\n[HIGH] Possible Brute Force Attack")
        print("Source IP:", ip)
        print("Target Account:", account)
        print("Failed Attempts:", attempts)
        print("Action: Investigate this IP immediately.")

        total_alerts += 1
        high_alerts += 1


    elif attempts >= 5:

        print("\n[MEDIUM] Repeated Failed Login Attempts")
        print("Source IP:", ip)
        print("Target Account:", account)
        print("Failed Attempts:", attempts)
        print("Action: Monitor this IP for further activity.")

        total_alerts += 1
        medium_alerts += 1


    elif attempts > 0:

        print("\n[LOW] Failed Login Activity")
        print("Source IP:", ip)
        print("Target Account:", account)
        print("Failed Attempts:", attempts)
        print("Action: Review the failed login activity.")

        total_alerts += 1
        low_alerts += 1


# ==========================================
# POSSIBLE ACCOUNT COMPROMISE
# ==========================================

for event in suspicious_successes:

    print(
        "\n[CRITICAL] Successful Login After Multiple Failures"
    )

    print("Source IP:", event["ip"])
    print("Account:", event["user"])
    print("Previous Failed Attempts:", event["failures"])

    print(
        "Action: Investigate the account and source IP immediately."
    )

    total_alerts += 1
    critical_alerts += 1


# ==========================================
# ALERT SUMMARY
# ==========================================

print("\n" + "=" * 55)
print("ALERT SUMMARY")
print("=" * 55)

print("Total Alerts:", total_alerts)
print("Critical Severity:", critical_alerts)
print("High Severity:", high_alerts)
print("Medium Severity:", medium_alerts)
print("Low Severity:", low_alerts)


# ==========================================
# COMPLETE
# ==========================================

print("\n" + "=" * 55)
print("ANALYSIS COMPLETE")
print("=" * 55)