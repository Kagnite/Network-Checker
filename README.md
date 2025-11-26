# NetProbe v1.0 – Professional Network Diagnostic Utility

**NetProbe** is a lightweight, dependency-free Python tool designed for DevOps engineers and System Administrators. It provides instant network diagnostics, connectivity checks, and continuous latency monitoring with anomaly detection — all using only the Python Standard Library.

---

## 🚀 Features

- **Cross-Platform:** Fully compatible with Windows, Linux, and macOS  
- **Local Network Discovery:** Automatically detects Local IP, Subnet Mask, and Default Gateway without external tools  
- **Connectivity Analysis:**
  - TCP connectivity checks to major infrastructure (Google DNS, YouTube)
  - Internet status detection (Open vs. Filtered)
  - HTTP service checks (e.g., Hamrah Academy)
- **Monitoring Mode (DevOps-Friendly):**
  - Continuous latency tracking
  - **Anomaly Detection:** Alerts when latency exceeds 2× the baseline standard deviation
  - **Data Logging:** Saves history to `network_history.json` and exports raw data to `network_history.csv`
- **Zero Dependencies:** Requires no external packages (no `pip install` needed)

---

## 📋 Requirements

- **Python 3.6 or higher**

---

## 🛠 Usage

### 1. Standard Diagnostic Run

```bash
python network_checker.py
```
### 2. Monitoring Mode (Continuous)

```
# Default interval (60 seconds)
python network_checker.py --monitor

# Custom interval (e.g., every 10 seconds)
python network_checker.py --monitor --interval 10
```
Stop monitoring using Ctrl + C.

### 3. JSON Output (Automation-Friendly)

```
python network_checker.py --json
```

📊 Output Files (Monitoring Mode)

network_history.json — Baseline history data

network_history.csv — Raw logs for analysis (Excel, Sheets, etc.)

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen)
.
# NetProbe v1.0 - Professional Network Diagnostic Utility
...












