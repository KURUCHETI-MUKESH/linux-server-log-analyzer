
# Linux Server Log Analyzer
# Task 6: Automated Report Generation

from collections import Counter
from datetime import datetime
import csv

LOG_FILE = "logs/sample.log"
TXT_REPORT = "reports/log_report.txt"
CSV_REPORT = "reports/log_report.csv"

FAILED_LOGIN_THRESHOLD = 3


def analyze_logs():

    log_levels = []
    error_messages = []
    warning_messages = []
    failed_logins = Counter()

    # Read and analyze the log file
    with open(LOG_FILE, "r") as file:

        for line in file:

            parts = line.strip().split()

            if len(parts) < 4:
                continue

            level = parts[2]
            message = " ".join(parts[3:])

            log_levels.append(level)

            if level == "ERROR":
                error_messages.append(message)

            elif level == "WARNING":
                warning_messages.append(message)

            # Detect failed login attempts
            if "Failed login for user " in message:

                username = message.split(
                    "Failed login for user ", 1
                )[1].strip()

                failed_logins[username] += 1

    # Calculate statistics
    counts = Counter(log_levels)
    error_counts = Counter(error_messages)
    warning_counts = Counter(warning_messages)

    suspicious_users = {
        user: attempts
        for user, attempts in failed_logins.items()
        if attempts > FAILED_LOGIN_THRESHOLD
    }

    # Prepare report information
    report = []

    report.append("=" * 50)
    report.append("       LINUX SERVER LOG ANALYZER")
    report.append("=" * 50)

    report.append(f"Generated At: {datetime.now()}")
    report.append("")

    report.append("GENERAL LOG SUMMARY")
    report.append("-" * 50)
    report.append(f"Total Entries : {len(log_levels)}")
    report.append(f"INFO          : {counts['INFO']}")
    report.append(f"WARNING       : {counts['WARNING']}")
    report.append(f"ERROR         : {counts['ERROR']}")

    report.append("")
    report.append("ERROR ANALYSIS")
    report.append("-" * 50)

    for message, count in error_counts.most_common():
        report.append(f"{message}: {count} time(s)")

    report.append("")
    report.append("WARNING ANALYSIS")
    report.append("-" * 50)

    for message, count in warning_counts.most_common():
        report.append(f"{message}: {count} time(s)")

    report.append("")
    report.append("LOGIN ATTEMPT SUMMARY")
    report.append("-" * 50)

    for user, attempts in failed_logins.most_common():
        report.append(f"{user}: {attempts} failed attempt(s)")

    report.append("")
    report.append("SUSPICIOUS ACTIVITY")
    report.append("-" * 50)

    if suspicious_users:

        for user, attempts in suspicious_users.items():
            report.append(
                f"ALERT: {user} - {attempts} failed login attempts"
            )

    else:
        report.append("No suspicious login activity detected.")

    report.append("")
    report.append("=" * 50)
    report.append("             ANALYSIS COMPLETED")
    report.append("=" * 50)

    # Display report in terminal
    print("\n".join(report))

    # Save TXT report
    with open(TXT_REPORT, "w") as file:
        file.write("\n".join(report))

    # Save CSV report
    with open(CSV_REPORT, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(["Metric", "Value"])

        writer.writerow(["Total Entries", len(log_levels)])
        writer.writerow(["INFO", counts["INFO"]])
        writer.writerow(["WARNING", counts["WARNING"]])
        writer.writerow(["ERROR", counts["ERROR"]])

        for user, attempts in failed_logins.items():
            writer.writerow([
                f"Failed Login - {user}",
                attempts
            ])

        for user, attempts in suspicious_users.items():
            writer.writerow([
                f"Suspicious User - {user}",
                attempts
            ])

    print("\nReports generated successfully!")
    print(f"TXT Report: {TXT_REPORT}")
    print(f"CSV Report: {CSV_REPORT}")


if __name__ == "__main__":
    analyze_logs()
