
import streamlit as st
import pandas as pd
import plotly.express as px
from collections import Counter
from pathlib import Path
from datetime import datetime

# Project file paths
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "sample.log"
REPORT_DIR = BASE_DIR / "reports"

TXT_REPORT = REPORT_DIR / "log_report.txt"
CSV_REPORT = REPORT_DIR / "log_report.csv"

FAILED_LOGIN_THRESHOLD = 3

# Dashboard configuration
st.set_page_config(
    page_title="Linux Server Log Analyzer",
    page_icon="📊",
    layout="wide"
)

st.title("🖥️ Linux Server Log Analyzer")
st.caption("Server log monitoring, error detection and suspicious activity analysis")

# Read and analyze log file
def analyze_logs():

    entries = []
    log_levels = Counter()
    error_messages = Counter()
    warning_messages = Counter()
    failed_logins = Counter()

    if not LOG_FILE.exists():
        return None

    with open(LOG_FILE, "r") as file:

        for line in file:

            parts = line.strip().split()

            if len(parts) < 4:
                continue

            date = parts[0]
            time = parts[1]
            level = parts[2]
            message = " ".join(parts[3:])

            entries.append({
                "Date": date,
                "Time": time,
                "Level": level,
                "Message": message
            })

            log_levels[level] += 1

            if level == "ERROR":
                error_messages[message] += 1

            elif level == "WARNING":
                warning_messages[message] += 1

            if "Failed login for user " in message:

                username = message.split(
                    "Failed login for user ", 1
                )[1].strip()

                failed_logins[username] += 1

    return {
        "entries": entries,
        "levels": log_levels,
        "errors": error_messages,
        "warnings": warning_messages,
        "failed_logins": failed_logins
    }


# Analyze button
if st.button("🔄 Analyze Logs Again"):
    st.rerun()

data = analyze_logs()

if data is None:
    st.error("Log file not found. Check logs/sample.log.")
    st.stop()

entries = data["entries"]
levels = data["levels"]
errors = data["errors"]
warnings = data["warnings"]
failed_logins = data["failed_logins"]

total_entries = len(entries)
error_count = levels["ERROR"]
warning_count = levels["WARNING"]
info_count = levels["INFO"]

suspicious_users = {
    user: count
    for user, count in failed_logins.items()
    if count > FAILED_LOGIN_THRESHOLD
}

# Dashboard summary
st.subheader("System Log Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Entries", total_entries)
col2.metric("INFO Messages", info_count)
col3.metric("WARNING Messages", warning_count)
col4.metric("ERROR Messages", error_count)

st.divider()

# Log level chart
st.subheader("Log Level Distribution")

chart_data = pd.DataFrame({
    "Log Level": ["INFO", "WARNING", "ERROR"],
    "Count": [info_count, warning_count, error_count]
})

fig = px.pie(
    chart_data,
    names="Log Level",
    values="Count",
    hole=0.45,
    title="Distribution of Log Messages"
)

st.plotly_chart(fig, use_container_width=True)

# Error and warning analysis
left, right = st.columns(2)

with left:

    st.subheader("Most Common Errors")

    if errors:

        error_df = pd.DataFrame(
            errors.most_common(),
            columns=["Error Message", "Occurrences"]
        )

        fig = px.bar(
            error_df,
            x="Occurrences",
            y="Error Message",
            orientation="h",
            title="Repeated Errors"
        )

        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(error_df, use_container_width=True)

    else:
        st.success("No errors detected.")

with right:

    st.subheader("Warning Analysis")

    if warnings:

        warning_df = pd.DataFrame(
            warnings.most_common(),
            columns=["Warning Message", "Occurrences"]
        )

        fig = px.bar(
            warning_df,
            x="Occurrences",
            y="Warning Message",
            orientation="h",
            title="Warning Frequency"
        )

        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(warning_df, use_container_width=True)

    else:
        st.success("No warnings detected.")

st.divider()

# Suspicious login activity
st.subheader("🔐 Suspicious Login Activity")

if suspicious_users:

    st.error("Suspicious login activity detected!")

    suspicious_df = pd.DataFrame(
        [
            {"Username": user, "Failed Attempts": count,
             "Status": "SUSPICIOUS"}
            for user, count in suspicious_users.items()
        ]
    )

    st.dataframe(suspicious_df, use_container_width=True)

else:
    st.success("No suspicious login activity detected.")

if failed_logins:

    login_df = pd.DataFrame(
        [
            {"Username": user, "Failed Attempts": count}
            for user, count in failed_logins.most_common()
        ]
    )

    st.subheader("Login Attempt Summary")
    st.dataframe(login_df, use_container_width=True)

st.divider()

# Recent log entries
st.subheader("Recent Log Entries")

if entries:

    recent_df = pd.DataFrame(entries[-10:][::-1])

    st.dataframe(
        recent_df,
        use_container_width=True,
        hide_index=True
    )

# Report downloads
st.divider()
st.subheader("📥 Download Reports")

download_col1, download_col2 = st.columns(2)

with download_col1:

    if TXT_REPORT.exists():

        with open(TXT_REPORT, "rb") as file:

            st.download_button(
                label="Download TXT Report",
                data=file.read(),
                file_name="log_report.txt",
                mime="text/plain"
            )

    else:
        st.warning("TXT report not found. Run the analyzer first.")

with download_col2:

    if CSV_REPORT.exists():

        with open(CSV_REPORT, "rb") as file:

            st.download_button(
                label="Download CSV Report",
                data=file.read(),
                file_name="log_report.csv",
                mime="text/csv"
            )

    else:
        st.warning("CSV report not found. Run the analyzer first.")

# Footer
st.divider()

st.caption(
    f"Linux Server Log Analyzer | "
    f"Last dashboard analysis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)
