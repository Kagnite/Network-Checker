# گزارش فنی: پیاده‌سازی ابزار بررسی شبکه (Network Checker)

## 1. مرور کلی

این مستند، گزارش پیاده‌سازی اسکریپت **Network Checker** است که به عنوان بخشی از آزمون ورودی آماده شده است.  
هدف این پروژه، نوشتن ابزاری بود که وضعیت **شبکه محلی** و **اتصال اینترنت** را بررسی کند.  

همچنین، یک قابلیت **مانیتورینگ مداوم (Continuous Monitoring)** برای رصد **نوسانات شبکه (Latency)** نیز به پروژه اضافه شده است.

---

## 2. اهداف و چالش‌های پیاده‌سازی

تمرکز اصلی من در این کد، **عدم وابستگی به کتابخانه‌های خارجی (Non-standard libraries)** و **عملکرد صحیح روی سیستم‌عامل‌های مختلف** بود.

### موارد پوشش داده شده:

- **سازگاری چند-لتفرمی (Cross-Platform):**  
  اسکریپت به صورت خودکار سیستم‌عامل را تشخیص داده و فرمان مناسب (مثل `ipconfig` در ویندوز یا فایل `/proc/net/route` در لینوکس) را اجرا می‌کند.

- **تست اتصال قابل اطمینان:**  
  به جای استفاده صرف از `ping` (که ممکن است بسته باشد)، از **TCP Socket** روی پورت‌های `53` و `443` استفاده شد تا اتصال واقعی به سرویس‌ها تست شود.

- **بررسی سلامت `HTTP`:**
  وضعیت پاسخ‌دهی سایت **"همراه آکادمی"** و زمان پاسخ آن اندازه‌گیری می‌شود.

- **قابلیت اضافه (Bonus):**  
  فلگ `--monitor` برای اجرای مداوم و شناسایی لحظاتی که شبکه دچار اختلال می‌شود.

---

## 3. نحوه اجرا

### بررسی استاندارد (پیش‌فرض)
اجرای یک‌بارِ تست و نمایش گزارش در ترمینال:

```bash
python3 network_checker.py
```
### خروجی JSON (برای پردازش‌های بعدی)

```bash
python3 network_checker.py --json
‍‍
```

### حالت مانیتورینگ (قابلیت اضافه)

این حالت برای دیباگ کردن **قطعی‌های لحظه‌ای شبکه** اضافه شده است:

```bash
python3 network_checker.py --monitor --interval 30

```

## 3. رویکرد فنی (Technical Approach)

### چالش دریافت اطلاعات شبکه
یکی از چالش‌های اصلی، دریافت **Gateway** و **Subnet** بدون نصب پکیج‌هایی مثل `netifaces` بود.

**راهکار:**  
من برای هر سیستم‌عامل (لینوکس، ویندوز، مک) یک تابع جداگانه نوشتم که خروجی دستورات سیستمی را با استفاده از **Regex** پردازش و اطلاعات مورد نیاز را استخراج می‌کند.

### منطق بررسی اتصال
برای تشخیص دقیق وضعیت اینترنت، از دو هدف متفاوت استفاده کردم:

- **Google DNS (8.8.8.8):**  
  برای اطمینان از متصل بودن اینترنت جهانی.

- **YouTube:**  
  برای تشخیص اینکه آیا اینترنت **"آزاد"** است یا **"فیلتر شده"**.

------------------------------------------------------------------------

## 4. توضیح فلگ‌ها

  فلگ                      توضیح
  ------------------------ -------------------------------------------
  `--json`                 خروجی JSON برای اسکریپت‌ها یا API
  `--monitor`              حالت مانیتورینگ مداوم
  `--interval <seconds>`   فاصله زمانی بین هر تست در حالت مانیتورینگ

------------------------------------------------------------------------

## 5. نمونه خروجی اجرا شده

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

## 6. تحلیل نتایج (Analysis of the Result)

بر اساس لاگ بالا که روی سیستم من اجرا شد:

- **شبکه محلی:**  
  اسکریپت به درستی **IP خصوصی** و ساب‌نت `/28` را تشخیص داده است.

- **وضعیت فیلترینگ:**  
  اتصال به گوگل با تاخیر کم برقرار است، اما اتصال به یوتیوب **Refused** شده که نشان‌دهنده محدودیت روی شبکه است.

- **پرفورمنس:**  
  درخواست HTTP به سایت هدف با موفقیت انجام شد اما زمان پاسخ (~۴.۵ ثانیه) نشان‌دهنده **کندی شبکه** در لحظه تست است.

------------------------------------------------------------------------

## 7. نتیجه‌گیری و مسیر بهبود (Future Improvements)

این اسکریپت نیازهای صورت مسئله را برطرف می‌کند.  
با این حال، اگر قرار بود این ابزار در محیط **Production** استفاده شود، این تغییرات را اعمال می‌کردم:

- **استفاده از کتابخانه‌ای مثل `psutil`:**  
  برای مدیریت تمیزتر کارت‌های شبکه (به جای Regex روی متن).

- **پیاده‌سازی `asyncio`:**  
  برای چک کردن همزمان (**Parallel**) اتصال‌ها و افزایش سرعت اجرا.


------------------------------------------------------------------------

---

# English Version

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
