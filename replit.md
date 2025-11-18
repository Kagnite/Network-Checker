# Network Checker - Professional DevOps Edition

## Project Overview

A comprehensive network diagnostic and monitoring tool designed for DevOps professionals. The tool performs network connectivity checks, identifies internet filtering, and tracks latency trends over time to detect anomalies.

## Recent Changes (November 18, 2025)

### Major Improvements

#### 1. Enhanced Windows Network Info Extraction
**Problem Solved:** The original `get_windows_net_info` function frequently returned "N/A" for subnet mask due to fragile regex patterns that couldn't handle variations in `ipconfig /all` output formatting.

**Solution Implemented:**
- **Multi-Strategy Parsing Architecture**
  - Strategy 1: Advanced regex patterns with flexible whitespace matching
  - Strategy 2: Line-by-line state machine parser as fallback
  - Multiple regex patterns per field with increasing flexibility

- **Key Improvements:**
  - Handles variations in spacing, tabs, and separators between field names and values
  - Robust adapter block detection to isolate the correct network interface
  - Graceful fallback mechanisms ensure maximum reliability
  - Uses only Python standard library (subprocess, re, socket, struct)

- **New Helper Functions:**
  - `_extract_adapter_block_strategy1()`: Extracts network adapter configuration block
  - `_parse_ipconfig_line_by_line()`: Fallback parser using state machine approach

#### 2. Network Latency Trend Monitoring (NEW DevOps Feature)
**Purpose:** Transform the diagnostic tool into a lightweight monitoring solution for tracking network performance over time.

**Capabilities:**
- **Continuous Monitoring:** Run automated checks at configurable intervals
- **Historical Data Tracking:** Store results in JSON and CSV formats
- **Baseline Establishment:** Calculate min/max/avg latency for each target
- **Anomaly Detection:** Alert when latency exceeds 2 standard deviations from baseline
- **Statistical Analysis:** Track standard deviation, median, and sample counts
- **Export for Analysis:** CSV output compatible with spreadsheet tools

**Usage Examples:**
```bash
# Standard single check
python network_checker.py

# JSON output for scripting
python network_checker.py --json

# Continuous monitoring (60 second intervals)
python network_checker.py --monitor

# Custom monitoring interval (every 30 seconds)
python network_checker.py --monitor --interval 30
```

**Output Files:**
- `network_history.json`: Complete historical data with all check details
- `network_history.csv`: CSV format for spreadsheet analysis and reporting

**DevOps Use Cases:**
- Detect gradual network degradation before critical failures
- Establish and track SLA compliance
- Root cause analysis using historical correlation
- Generate incident reports with documented evidence
- Monitor restricted network environments for connectivity issues

## Project Architecture

### Core Components

1. **Platform-Specific Network Info Functions**
   - `get_windows_net_info()`: Windows network configuration (Enhanced)
   - `get_linux_net_info()`: Linux network configuration via /proc and ip command
   - `get_macos_net_info()`: macOS network configuration via route and ifconfig

2. **Connectivity Testing**
   - `check_tcp_connection()`: TCP socket connectivity with retry logic
   - `check_http_service()`: HTTP/HTTPS service verification
   - `analyze_internet_status()`: Determine filtering/restriction status

3. **Monitoring & Analytics (NEW)**
   - `load_history()` / `save_history()`: Historical data persistence
   - `calculate_statistics()`: Min/max/avg/stddev calculation
   - `detect_anomaly()`: Statistical anomaly detection (2-sigma threshold)
   - `monitoring_mode()`: Continuous monitoring loop
   - `save_to_csv()`: Export data for external analysis

4. **Reporting**
   - `print_report()`: Standard diagnostic report
   - `print_monitoring_report()`: Monitoring report with trend analysis
   - Color-coded output (auto-disabled on Windows for compatibility)

### Dependencies

**Standard Library Only** - No third-party packages required:
- `socket`, `subprocess`, `re`, `struct`: Network operations
- `argparse`, `json`, `csv`: Data handling
- `time`, `datetime`: Timing and timestamps
- `platform`, `ipaddress`: System and network utilities

## User Preferences

- **Code Style:** Professional DevOps standards with comprehensive documentation
- **Reliability:** Multiple fallback strategies for maximum robustness
- **Portability:** Cross-platform support (Windows, Linux, macOS)
- **Standard Library:** No external dependencies for easy deployment

## Technical Notes

### Windows Parsing Strategy

The enhanced Windows parser uses a two-tier approach:

1. **Regex-Based Extraction:**
   - Locates adapter block containing the active IP address
   - Tries multiple regex patterns with increasing flexibility
   - Handles common `ipconfig` output variations

2. **Line-by-Line Fallback:**
   - State machine approach for maximum reliability
   - Finds IP address first, then scans surrounding lines
   - Extracts any IPv4 address patterns near subnet/gateway keywords

### Monitoring Algorithm

1. **Baseline Building:** Collects latency samples over time
2. **Statistical Analysis:** Calculates mean and standard deviation
3. **Anomaly Detection:** Flags values > mean + (2 × stddev)
4. **Persistence:** Maintains rolling history (max 1000 checks)

## Future Enhancements (Potential)

- Unit tests with mock ipconfig outputs
- Logging for regex matching diagnostics
- Multiple active adapter handling with priority selection
- Performance optimization for large datasets
- Additional monitoring targets (custom hosts/ports)
- Alert thresholds and notification systems
