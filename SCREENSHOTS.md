# CyberForensics Toolkit - Visual Guide

## What You'll See After Deployment

This guide shows you what to expect when using the CyberForensics Toolkit web portal.

---

## 1. Main Dashboard (http://localhost:5000)

### Layout Overview:

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔍 CyberForensics Toolkit                     [Home] [Reports]     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    WELCOME TO CYBERFORENSICS                 │  │
│  │            Advanced Digital Investigation Platform           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐              │
│  │   42    │  │   156   │  │   8,234 │  │   98%   │              │
│  │ Reports │  │Evidence │  │ Records │  │ Uptime  │              │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘              │
│                                                                      │
│  FORENSIC TOOLS                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │ 📁 File         │  │ 🌐 Network      │  │ 🦠 Malware      │   │
│  │    Forensics    │  │    Analysis     │  │    Analysis     │   │
│  │                 │  │                 │  │                 │   │
│  │ Recover files,  │  │ Analyze PCAP,   │  │ Static analysis,│   │
│  │ extract metadata│  │ monitor traffic │  │ detect threats  │   │
│  │                 │  │                 │  │                 │   │
│  │ [Launch Tool]   │  │ [Launch Tool]   │  │ [Launch Tool]   │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │ 🔐 Password     │  │ 👤 Social Media │  │ 🗺️  Geolocation │   │
│  │    Recovery     │  │    OSINT        │  │                 │   │
│  │                 │  │                 │  │                 │   │
│  │ Crack hashes,   │  │ Profile search, │  │ IP tracking,    │   │
│  │ analyze patterns│  │ cross-platform  │  │ interactive maps│   │
│  │                 │  │                 │  │                 │   │
│  │ [Launch Tool]   │  │ [Launch Tool]   │  │ [Launch Tool]   │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐                         │
│  │ 📧 Email        │  │ 🎯 User         │                         │
│  │    Forensics    │  │    Attribution  │                         │
│  │                 │  │                 │                         │
│  │ Header analysis,│  │ Correlate data, │                         │
│  │ sender tracking │  │ identify users  │                         │
│  │                 │  │                 │                         │
│  │ [Launch Tool]   │  │ [Launch Tool]   │                         │
│  └─────────────────┘  └─────────────────┘                         │
│                                                                      │
│  QUICK ACTIONS                                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Quick IP Lookup                                             │  │
│  │ [Enter IP Address: ____________] [Analyze]                  │  │
│  │                                                              │  │
│  │ Quick Hash Crack                                            │  │
│  │ [Enter Hash: ____________________] [Crack]                  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Features on Dashboard:
- **Statistics Cards**: Live system statistics
- **8 Tool Cards**: Click any card to launch that tool
- **Quick Actions**: Instant IP lookup and hash cracking
- **Navigation Bar**: Access reports and other pages

---

## 2. Geolocation Tool (http://localhost:5000/geolocation)

### Interactive Map Interface:

```
┌─────────────────────────────────────────────────────────────────────┐
│  🗺️  IP Geolocation & Network Tracking                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                                                               │  │
│  │                 INTERACTIVE WORLD MAP                         │  │
│  │                                                               │  │
│  │        ◉ USA                                                  │  │
│  │         ╲                                                     │  │
│  │          ╲───→ ◉ UK                                           │  │
│  │                  ╲                                            │  │
│  │                   ╲───→ ◉ Germany                             │  │
│  │                          ╲                                    │  │
│  │                           ╲───→ ⚠ Russia (High Risk)          │  │
│  │                                                               │  │
│  │  Legend:  ● Safe   ● Moderate   ⚠ High Risk   ⛔ Critical    │  │
│  │                                                               │  │
│  │  [Zoom In] [Zoom Out] [Reset View] [Export Map]              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  IP ANALYSIS                                                        │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ IP Address: [8.8.8.8_____________] [Analyze]                │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  TRACEROUTE                                                         │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Destination: [example.com________] [Trace Route]            │  │
│  │ ☑ Generate Map                                               │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  RESULTS                                                            │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ IP: 8.8.8.8                                                  │  │
│  │ Location: Mountain View, CA, USA                             │  │
│  │ Coordinates: 37.4056° N, 122.0775° W                         │  │
│  │ ISP: Google LLC                                              │  │
│  │ Risk Score: 5/100 (Safe)                                     │  │
│  │ Distance from previous: 2,847 km                             │  │
│  │                                                               │  │
│  │ [View on Map] [Export Report]                                │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### What You Can Do:
- **Analyze IPs**: Enter any IP address for instant geolocation
- **Trace Routes**: See the complete path packets take
- **Interactive Map**: Click markers for detailed popup info
- **Zoom & Pan**: Explore the world map freely
- **Color Coding**: Green (safe), Yellow (moderate), Red (high risk)
- **Export**: Download maps as standalone HTML files

---

## 3. Email Forensics (http://localhost:5000/email-forensics)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📧 Email Forensics & Sender Analysis                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  UPLOAD EMAIL                                                       │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ [Choose .eml file] phishing_email.eml                       │  │
│  │                                                              │  │
│  │ ☑ Trace Sender Location                                      │  │
│  │ ☑ Analyze Headers                                            │  │
│  │ ☑ Check Authentication (SPF/DKIM/DMARC)                      │  │
│  │ ☑ Generate Route Map                                         │  │
│  │                                                              │  │
│  │ [Analyze Email]                                              │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ANALYSIS RESULTS                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ From: admin@secure-bank.com                                  │  │
│  │ Real From: hacker@malicious.ru  ⚠️ SPOOFED!                  │  │
│  │                                                              │  │
│  │ Authentication:                                              │  │
│  │   SPF: ❌ FAIL                                                │  │
│  │   DKIM: ❌ FAIL                                               │  │
│  │   DMARC: ❌ FAIL                                              │  │
│  │                                                              │  │
│  │ Risk Level: ⛔ CRITICAL - Likely Phishing                    │  │
│  │                                                              │  │
│  │ Email Path (Traced):                                         │  │
│  │   1. 185.220.101.5 (Russia) → Moscow, RU                     │  │
│  │   2. 198.51.100.23 (Netherlands) → Amsterdam, NL             │  │
│  │   3. 192.0.2.45 (USA) → New York, NY                         │  │
│  │   4. Final Delivery                                          │  │
│  │                                                              │  │
│  │ [View Route Map] [Download Report]                           │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### What It Detects:
- ✅ Sender spoofing
- ✅ Failed email authentication
- ✅ Suspicious mail server routes
- ✅ Geographic anomalies
- ✅ Phishing indicators

---

## 4. Password Recovery (http://localhost:5000/password-recovery)

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔐 Password Recovery & Hash Analysis                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  HASH CRACKING                                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Hash Value:                                                  │  │
│  │ [5f4dcc3b5aa765d61d8327deb882cf99____________________]       │  │
│  │                                                              │  │
│  │ Algorithm:                                                   │  │
│  │ [MD5 ▼] SHA1  SHA256  NTLM  bcrypt                          │  │
│  │                                                              │  │
│  │ Attack Method:                                               │  │
│  │ ◉ Dictionary Attack                                          │  │
│  │ ○ Brute Force                                                │  │
│  │ ○ AI-Assisted Smart Attack                                   │  │
│  │                                                              │  │
│  │ Wordlist: [common_passwords.txt ▼]                           │  │
│  │                                                              │  │
│  │ [Start Cracking]                                             │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  PROGRESS                                                           │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ ████████████████████░░░░░░░░░░ 67%                          │  │
│  │                                                              │  │
│  │ Passwords Tested: 67,234                                     │  │
│  │ Speed: 12,456 hashes/sec                                     │  │
│  │ Elapsed Time: 5 seconds                                      │  │
│  │ Estimated Time Remaining: 3 seconds                          │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  RESULT                                                             │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ ✅ SUCCESS!                                                   │  │
│  │                                                              │  │
│  │ Hash: 5f4dcc3b5aa765d61d8327deb882cf99                       │  │
│  │ Password: password                                           │  │
│  │                                                              │  │
│  │ Strength Analysis:                                           │  │
│  │   - Very Weak (8/100)                                        │  │
│  │   - Common dictionary word                                   │  │
│  │   - No special characters                                    │  │
│  │   - Too short (8 characters)                                 │  │
│  │                                                              │  │
│  │ Time to Crack: 7.3 seconds                                   │  │
│  │                                                              │  │
│  │ [Save Result] [Crack Another]                                │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Supported Algorithms:
- MD5, SHA1, SHA256, SHA512
- NTLM, LM (Windows hashes)
- bcrypt, scrypt (modern)

### Attack Methods:
- **Dictionary**: Fast, uses wordlists
- **Brute Force**: Tries all combinations
- **AI-Assisted**: Smart pattern recognition

---

## 5. Network Analysis (http://localhost:5000/network-analysis)

```
┌─────────────────────────────────────────────────────────────────────┐
│  🌐 Network Traffic Analysis                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  UPLOAD PCAP FILE                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ [Choose .pcap file] network_capture.pcap  (2.3 GB)          │  │
│  │                                                              │  │
│  │ [Upload & Analyze]                                           │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ANALYSIS RESULTS                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ SUMMARY                                                      │  │
│  │ ├─ Total Packets: 1,234,567                                 │  │
│  │ ├─ Duration: 2h 34m 12s                                      │  │
│  │ ├─ Unique IPs: 847                                           │  │
│  │ └─ Protocols: TCP (78%), UDP (19%), ICMP (3%)               │  │
│  │                                                              │  │
│  │ ⚠️ THREATS DETECTED: 23                                       │  │
│  │                                                              │  │
│  │ 🔴 Port Scan Detected                                         │  │
│  │    Source: 192.168.1.105                                     │  │
│  │    Target: 10.0.0.0/24                                       │  │
│  │    Ports Scanned: 1-65535                                    │  │
│  │    Time: 2026-01-09 14:23:15                                 │  │
│  │                                                              │  │
│  │ 🔴 SYN Flood Attack                                           │  │
│  │    Source: 203.0.113.45 (External)                           │  │
│  │    Target: 192.168.1.10:80                                   │  │
│  │    Packets: 45,678 in 2 minutes                              │  │
│  │                                                              │  │
│  │ 🟡 DNS Tunneling Suspected                                    │  │
│  │    Domain: x3k9f2j.malicious.com                             │  │
│  │    Queries: 2,345 (unusual volume)                           │  │
│  │                                                              │  │
│  │ TOP TALKERS                                                  │  │
│  │   1. 192.168.1.10 → 203.0.113.50 (1.2 GB)                    │  │
│  │   2. 10.0.0.5 → 8.8.8.8 (845 MB)                             │  │
│  │   3. 172.16.0.20 → 198.51.100.1 (623 MB)                     │  │
│  │                                                              │  │
│  │ [Download Full Report] [Generate Timeline]                   │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### What It Detects:
- Port scanning attempts
- DDoS/DoS attacks (SYN floods)
- DNS tunneling
- Suspicious protocols
- Unusual traffic patterns
- Data exfiltration

---

## 6. Malware Analysis (http://localhost:5000/malware-analysis)

```
┌─────────────────────────────────────────────────────────────────────┐
│  🦠 Malware Static Analysis                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  UPLOAD SAMPLE                                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ [Choose file] suspicious.exe  (2.4 MB)                       │  │
│  │                                                              │  │
│  │ ⚠️ File will be analyzed statically (no execution)           │  │
│  │                                                              │  │
│  │ [Analyze Sample]                                             │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ANALYSIS REPORT                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ FILE INFORMATION                                             │  │
│  │ ├─ Name: suspicious.exe                                      │  │
│  │ ├─ Size: 2,456,789 bytes                                     │  │
│  │ ├─ MD5: a3f2b1c8e9d4f5a6b7c8d9e0f1a2b3c4                     │  │
│  │ └─ SHA256: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p...               │  │
│  │                                                              │  │
│  │ RISK ASSESSMENT: ⛔ 87/100 (CRITICAL)                        │  │
│  │                                                              │  │
│  │ PE ANALYSIS                                                  │  │
│  │ ├─ Type: Windows PE32 executable                            │  │
│  │ ├─ Compiler: Microsoft Visual C++ 2019                      │  │
│  │ ├─ Sections: .text, .data, .rsrc, .reloc                    │  │
│  │ └─ Entropy: 7.98/8.0 ⚠️ PACKED/ENCRYPTED                    │  │
│  │                                                              │  │
│  │ SUSPICIOUS APIs DETECTED (42):                               │  │
│  │ 🔴 CreateRemoteThread         (Code injection)               │  │
│  │ 🔴 WriteProcessMemory         (Memory manipulation)          │  │
│  │ 🔴 VirtualAllocEx             (Memory allocation)            │  │
│  │ 🔴 SetWindowsHookEx           (Keylogging)                   │  │
│  │ 🔴 InternetOpenUrl            (Network communication)        │  │
│  │ 🔴 RegSetValueEx              (Registry modification)        │  │
│  │ 🟡 GetAsyncKeyState           (Keyboard monitoring)          │  │
│  │ 🟡 GetProcAddress             (Dynamic API loading)          │  │
│  │                                                              │  │
│  │ STRINGS FOUND:                                               │  │
│  │ - "http://malicious-c2.com/data"                             │  │
│  │ - "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"            │  │
│  │ - "admin123"                                                 │  │
│  │ - "keylog.txt"                                               │  │
│  │                                                              │  │
│  │ SIGNATURES MATCHED:                                          │  │
│  │ ✓ Trojan.Generic.Keylogger (95% confidence)                  │  │
│  │ ✓ Backdoor.RemoteAccess (82% confidence)                     │  │
│  │                                                              │  │
│  │ RECOMMENDATION: ⛔ DO NOT EXECUTE - Highly Malicious         │  │
│  │                                                              │  │
│  │ [Download Report] [Export IOCs]                              │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Analysis Includes:
- PE header inspection
- Entropy calculation (packing detection)
- Suspicious API detection (200+ APIs)
- String extraction
- Signature matching (YARA-like)
- Risk scoring

---

## 7. Social Media OSINT (http://localhost:5000/osint)

```
┌─────────────────────────────────────────────────────────────────────┐
│  👤 Social Media Intelligence Gathering                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PROFILE SEARCH                                                     │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Username: [john_doe___________]                              │  │
│  │                                                              │  │
│  │ Platforms:                                                   │  │
│  │ ☑ Twitter   ☑ Facebook   ☑ LinkedIn   ☑ Instagram           │  │
│  │ ☑ GitHub    ☑ Reddit     □ TikTok     □ YouTube             │  │
│  │                                                              │  │
│  │ [Search Profiles]                                            │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  RESULTS (5 profiles found)                                         │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ TWITTER: @john_doe                                           │  │
│  │ ├─ Joined: January 2015                                      │  │
│  │ ├─ Location: San Francisco, CA                               │  │
│  │ ├─ Followers: 1,234                                           │  │
│  │ ├─ Bio: "Software developer | Tech enthusiast"               │  │
│  │ └─ Activity Pattern: Most active 9AM-5PM PST                 │  │
│  │                                                              │  │
│  │ LINKEDIN: John Doe                                           │  │
│  │ ├─ Company: Tech Corp Inc.                                   │  │
│  │ ├─ Position: Senior Developer                                │  │
│  │ ├─ Location: San Francisco Bay Area                          │  │
│  │ └─ Email: john.doe@example.com                               │  │
│  │                                                              │  │
│  │ GITHUB: johndoe                                              │  │
│  │ ├─ Repositories: 42                                           │  │
│  │ ├─ Languages: Python, JavaScript, Go                         │  │
│  │ └─ Last Active: 2 days ago                                   │  │
│  │                                                              │  │
│  │ ✅ CROSS-PLATFORM CORRELATION                                 │  │
│  │ Confidence: 92% - Same person across all platforms           │  │
│  │                                                              │  │
│  │ BEHAVIORAL ANALYSIS                                          │  │
│  │ ├─ Timezone: UTC-8 (Pacific Time)                            │  │
│  │ ├─ Active Hours: Weekdays 9AM-6PM                            │  │
│  │ ├─ Bot Probability: 5% (Human)                               │  │
│  │ └─ Interests: Technology, Programming, AI                    │  │
│  │                                                              │  │
│  │ [View Network Graph] [Export Report]                         │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Capabilities:
- Cross-platform profile search
- Correlation analysis
- Activity pattern detection
- Timezone estimation
- Bot detection
- Network mapping

---

## 8. File Forensics (http://localhost:5000/file-forensics)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📁 File Recovery & Metadata Analysis                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  FILE RECOVERY                                                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Source: [disk.img___________] [Choose File]                 │  │
│  │                                                              │  │
│  │ File Types to Recover:                                       │  │
│  │ ☑ Images (JPG, PNG, GIF)                                     │  │
│  │ ☑ Documents (PDF, DOCX, XLSX)                                │  │
│  │ ☑ Videos (MP4, AVI, MOV)                                     │  │
│  │ ☑ Archives (ZIP, RAR, 7Z)                                    │  │
│  │                                                              │  │
│  │ [Start Recovery]                                             │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  RECOVERY PROGRESS                                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ ████████████████████████░░░░ 82%                            │  │
│  │                                                              │  │
│  │ Files Found: 347                                             │  │
│  │ Files Recovered: 284                                         │  │
│  │ Scanning: Sector 1,234,567 / 1,500,000                      │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  RECOVERED FILES                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ 📄 document.pdf                                              │  │
│  │    Size: 2.3 MB                                              │  │
│  │    Created: 2025-12-15 14:23:45                              │  │
│  │    Modified: 2025-12-15 14:25:12                             │  │
│  │    Deleted: 2025-12-20 09:15:33                              │  │
│  │    MD5: f3e4d5c6b7a8e9d0f1a2b3c4d5e6f7a8                     │  │
│  │    [Preview] [Download]                                      │  │
│  │                                                              │  │
│  │ 🖼️ photo.jpg                                                  │  │
│  │    Size: 5.1 MB                                              │  │
│  │    EXIF: Canon EOS 5D Mark IV                                │  │
│  │    GPS: 37.7749° N, 122.4194° W (San Francisco)              │  │
│  │    Date Taken: 2025-11-20 15:42:18                           │  │
│  │    [View Location] [Download]                                │  │
│  │                                                              │  │
│  │ [Download All] [Generate Report]                             │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Features:
- File carving from disk images
- 30+ file type support
- EXIF data extraction
- GPS coordinates from photos
- Timeline reconstruction
- Hash calculation

---

## 9. User Attribution (http://localhost:5000/attribution)

```
┌─────────────────────────────────────────────────────────────────────┐
│  🎯 Evidence Correlation & User Attribution                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  EVIDENCE SOURCES                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ Load evidence from previous analyses:                        │  │
│  │                                                              │  │
│  │ ☑ Network Analysis (192.168.1.105 → Multiple IPs)           │  │
│  │ ☑ Email Forensics (hacker@malicious.ru)                     │  │
│  │ ☑ IP Geolocation (Moscow, Russia)                           │  │
│  │ ☑ Social Media OSINT (@suspicious_user)                     │  │
│  │ ☑ Malware Analysis (C2: malicious-c2.com)                   │  │
│  │                                                              │  │
│  │ [Correlate Evidence]                                         │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ATTRIBUTION RESULTS                                                │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ 🎯 PRIMARY SUSPECT IDENTIFIED                                 │  │
│  │                                                              │  │
│  │ Suspect ID: ATTACKER-2026-001                                │  │
│  │ Confidence Level: 89% (High)                                 │  │
│  │                                                              │  │
│  │ CORRELATED INDICATORS:                                       │  │
│  │ ├─ IP Address: 185.220.101.5 (appears in 4 sources)         │  │
│  │ ├─ Email: hacker@malicious.ru                                │  │
│  │ ├─ Domain: malicious-c2.com                                  │  │
│  │ ├─ Location: Moscow, Russia                                  │  │
│  │ ├─ Timezone: UTC+3 (consistent across activity)             │  │
│  │ └─ Social Media: @suspicious_user (Twitter)                  │  │
│  │                                                              │  │
│  │ ATTACK TIMELINE:                                             │  │
│  │ 2026-01-08 14:23 UTC - Port scan initiated                   │  │
│  │ 2026-01-08 14:45 UTC - Phishing email sent                   │  │
│  │ 2026-01-08 15:12 UTC - Malware deployed                      │  │
│  │ 2026-01-08 16:30 UTC - Data exfiltration detected            │  │
│  │                                                              │  │
│  │ THREAT ACTOR PROFILE:                                        │  │
│  │ ├─ Sophistication: Medium-High                               │  │
│  │ ├─ Motivation: Financial (ransomware indicators)             │  │
│  │ ├─ TTPs: APT28-like behavior patterns                        │  │
│  │ └─ Infrastructure: Bulletproof hosting, Russia               │  │
│  │                                                              │  │
│  │ RECOMMENDED ACTIONS:                                         │  │
│  │ 1. Block IP 185.220.101.5 at firewall                        │  │
│  │ 2. Quarantine infected systems                               │  │
│  │ 3. Reset compromised credentials                             │  │
│  │ 4. Report to law enforcement                                 │  │
│  │ 5. Implement email filtering for malicious.ru                │  │
│  │                                                              │  │
│  │ [Export Law Enforcement Package] [Generate Report]           │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### What It Does:
- Correlates evidence from all 7 other tools
- Identifies common indicators (IPs, emails, domains)
- Reconstructs attack timeline
- Builds threat actor profile
- Generates suspect confidence score
- Creates law enforcement packages

---

## 10. Reports Viewer (http://localhost:8080/reports)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📊 Generated Reports                                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ALL REPORTS                                                        │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                                                              │  │
│  │ 📄 IP_Analysis_8.8.8.8.html                                  │  │
│  │    Date: 2026-01-09 10:23:15                                 │  │
│  │    Size: 245 KB                                              │  │
│  │    [View] [Download]                                         │  │
│  │                                                              │  │
│  │ 🗺️ Route_Map_example.com.html                                │  │
│  │    Date: 2026-01-09 10:45:33                                 │  │
│  │    Size: 1.2 MB                                              │  │
│  │    [View] [Download]                                         │  │
│  │                                                              │  │
│  │ 📧 Email_Forensics_phishing.json                             │  │
│  │    Date: 2026-01-09 11:12:08                                 │  │
│  │    Size: 34 KB                                               │  │
│  │    [View] [Download]                                         │  │
│  │                                                              │  │
│  │ 🦠 Malware_Analysis_suspicious.exe.pdf                        │  │
│  │    Date: 2026-01-09 12:05:42                                 │  │
│  │    Size: 567 KB                                              │  │
│  │    [View] [Download]                                         │  │
│  │                                                              │  │
│  │ 🎯 Attribution_Report_ATTACKER-001.html                       │  │
│  │    Date: 2026-01-09 14:30:19                                 │  │
│  │    Size: 892 KB                                              │  │
│  │    [View] [Download]                                         │  │
│  │                                                              │  │
│  │ [Download All as ZIP] [Clear Old Reports]                    │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Report Types:
- **HTML**: Interactive reports with styling
- **JSON**: Machine-readable data
- **CSV**: Spreadsheet-compatible
- **Maps**: Standalone Leaflet.js visualizations

---

## Summary

The CyberForensics Toolkit provides a **professional, intuitive interface** for digital forensics investigations:

✅ **Easy to Use**: Point-and-click web interface
✅ **Visual**: Interactive maps, charts, timelines
✅ **Comprehensive**: 8 specialized tools
✅ **Integrated**: Evidence correlation across tools
✅ **Professional**: Export-ready reports for law enforcement

**Access it at:** http://localhost:5000 after running `deploy_windows.bat`

Ready to investigate! 🔍
