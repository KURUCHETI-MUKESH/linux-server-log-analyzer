# Linux Server Log Analyzer

A Python-based Linux server log analysis tool that analyzes log files, identifies errors and warnings, detects suspicious login activity, and generates automated reports through a Streamlit dashboard.

## Features

- Analyzes Linux server log files.
- Counts INFO, WARNING, and ERROR messages.
- Identifies frequently occurring errors and warnings.
- Tracks failed login attempts by username.
- Detects suspicious login activity using a configurable threshold.
- Generates TXT and CSV reports.
- Provides an interactive Streamlit dashboard.
- Displays recent log entries and log-level statistics.

## Technologies Used

- Python
- Linux (Ubuntu)
- Bash commands
- Streamlit
- Pandas
- Plotly
- Git and GitHub

## Project Structure

```text
linux-server-log-analyzer/
├── logs/
│   └── sample.log
├── scripts/
│   └── log_analyzer.py
├── reports/
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
