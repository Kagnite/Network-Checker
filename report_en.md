# Network Connectivity Checker - Entrance Task Submission
**Developer:** Hirad Babakhani

Comprehensive Report

## 1. Overview

This report details the solution implemented for the **Network Checker** task. The objective was to create a Python script that diagnoses local network configurations, checks internet connectivity, and verifies access to specific services. I also implemented a **continuous monitoring feature** to track latency over time.

------------------------------------------------------------------------

## 2. Project Goals & Implementation

My main goal was to write a script that works reliably across different operating systems (Linux, Windows, macOS) without relying on external non-standard libraries.

- **Cross-Platform Compatibility:**  
  Detects the operating system and uses the appropriate system commands  
  (such as `ipconfig` for Windows or `/proc/net/route` for Linux)  
  to parse network information.

- **Connectivity Checks:**  
  Uses TCP sockets to perform fast and reliable connection tests  
  to Google DNS and YouTube (to detect possible filtering).

- **HTTP Health Check:**  
  Verifies accessibility of **Hamrah Academy** and measures response time.

- **Bonus Feature:**  
  Includes a `--monitor` flag that allows the script  
  to run continuously and detect latency spikes or anomalies.
------------------------------------------------------------------------

## 3. How to Run

### Standard Check (Default)
Run the script to get a one-time diagnostic report:

```bash
    python3 network_checker.py
```

### JSON Output (For parsing)

```bash
    python3 network_checker.py --json
```

### Enable Continuous Monitoring

```bash
    python3 network_checker.py --monitor
```

### Set Monitoring Interval (default: 60 seconds)

```bash
    python3 network_checker.py --monitor --interval 30
```

------------------------------------------------------------------------

## 4. Technical Approach

### Local Network Detection
One of the challenges was getting the **Gateway** and **Subnet Mask** reliably on all OSs using only standard libraries.

**Solution:**  
I implemented specific parsing functions (`get_windows_net_info`, `get_linux_net_info`, etc.) that use regex to extract data from system command outputs.

---

### Connectivity Logic
Instead of just using `ping` (which might be blocked by firewalls), I used Python's **socket** library to attempt a TCP handshake on:

- **Port 53** (DNS)  
- **Port 443** (HTTPS)

This gives a more accurate representation of **application-level connectivity**.

---

### Result Interpretation
The script analyzes the results to give a summary:

- **Restricted:**  
  Google is reachable but YouTube is not (TCP connection refused/timeout).

- **Partial:**  
  High latency or HTTP errors occur.

- **No Internet:**  
  Connection to `8.8.8.8` fails.


## 5. Sample Output (Executed on my machine)


    NetProbe v1.0 - Network Diagnostic Utility (Linux)
    ============================================================

    [1] Local Network Configuration
      • IP Address : 172.20.10.4 (Private)
      • Subnet Mask: 255.255.255.240 (/28)
      • Gateway    : 172.20.10.1

    [2] Service Connectivity
      Target                    Status     Latency    Details
      ------------------------- ---------- ---------- ---------------
      Google DNS                OK         0.21ms     Connected
      Restricted (YouTube)      FAIL       -          Refused (Service Down/Blocked)

    [3] Hamrah Academy Access
      • URL: https://hamrah.academy
      • Result: OK - HTTP 200 (4570.83ms)

    ============================================================
    FINAL DIAGNOSIS: PARTIAL INTERNET (Check details)
    ============================================================

------------------------------------------------------------------------

## 6. Analysis of the Result

Based on the output above:

- **Local Network:**  
  The script correctly identified the private IP and the `/28` subnet mask.

- **Filtering:**  
  The connection to Google DNS was successful (low latency), but the connection to YouTube was refused.  
  This indicates that the internet is connected but likely **filtered**.

- **Performance:**  
  The HTTP check to **Hamrah Academy** took ~4.5 seconds, suggesting potential routing issues or network congestion at that moment.

## 7. Conclusion & Future Improvements

The script successfully performs the required checks.  
If I were to improve this further in a production environment, I would:

- **Use libraries like `psutil` or `netifaces`:**  
  For cleaner and more reliable network interface handling (avoiding regex parsing of command outputs).

- **Implement asynchronous checks (`asyncio`):**  
  To run all connection tests in parallel for significantly faster execution.
