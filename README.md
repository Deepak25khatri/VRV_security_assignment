# VRV Security Assignment
## Log File Analysis Tool

## Overview
The **Log File Analysis Tool** is a Python script that analyzes web server log files. It provides insights such as:
- Requests per IP address.
- Most accessed endpoints.
- Detection of suspicious activity based on failed login attempts exceeding a configurable threshold.

The tool outputs the results to the terminal and saves them in a CSV file for further analysis.

---

## Features
- **Log Parsing**: Extracts IP addresses, endpoints, and failed login attempts from log entries.
- **Suspicious Activity Detection**: Identifies IPs with failed login attempts exceeding a specified threshold.
- **CSV Export**: Saves the analysis results into a structured CSV file.
- **Command-Line Interface (CLI)**: Allows threshold and log file to be passed as arguments.

---

## Requirements
- **Python**: Version 3.7 or higher.
- **Dependencies**: Built-in modules (`re`, `sys`, `csv`, `collections`).

---

## Usage

1. **Run the script using Python**:
   ```bash
   python log_analysis.py [threshold] <log_file>
