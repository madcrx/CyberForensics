# CyberForensics Toolkit - Windows Deployment Guide

Complete step-by-step instructions for deploying and running the CyberForensics Toolkit on Windows using Docker.

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation Steps](#installation-steps)
3. [Building the Docker Containers](#building-the-docker-containers)
4. [Running the Toolkit](#running-the-toolkit)
5. [Accessing the Tools](#accessing-the-tools)
6. [Stopping the Toolkit](#stopping-the-toolkit)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Usage](#advanced-usage)

---

## Prerequisites

### 1. Install Docker Desktop for Windows

**Download and Install:**
1. Visit [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Download Docker Desktop installer
3. Run the installer (requires Administrator privileges)
4. Follow the installation wizard
5. **Restart your computer** when prompted

**System Requirements:**
- Windows 10 64-bit: Pro, Enterprise, or Education (Build 19041 or higher)
- OR Windows 11 64-bit: Pro, Enterprise, or Education
- WSL 2 feature enabled (installer will enable this)
- At least 4GB RAM (8GB recommended)
- Virtualization enabled in BIOS

**Verify Installation:**
1. Open **PowerShell** or **Command Prompt**
2. Run:
   ```cmd
   docker --version
   docker-compose --version
   ```
3. You should see version numbers (e.g., Docker version 24.x.x)

### 2. Configure Docker Desktop

1. **Start Docker Desktop** from Windows Start Menu
2. Wait for Docker Engine to start (whale icon in system tray turns green)
3. Right-click Docker icon → **Settings**
4. Under **Resources** → **Advanced**:
   - Set Memory to at least **4GB** (8GB recommended)
   - Set CPUs to at least **2** (4 recommended)
5. Click **Apply & Restart**

---

## Installation Steps

### Step 1: Download the Project

**Option A: Clone from Git (Recommended)**
1. Open **PowerShell** or **Command Prompt**
2. Navigate to where you want the project:
   ```cmd
   cd C:\Users\YourUsername\Documents
   ```
3. Clone the repository:
   ```cmd
   git clone <repository-url> CyberForensics
   cd CyberForensics
   ```

**Option B: Download ZIP**
1. Download the project ZIP file
2. Extract to `C:\Users\YourUsername\Documents\CyberForensics`
3. Open **PowerShell** or **Command Prompt**
4. Navigate to the folder:
   ```cmd
   cd C:\Users\YourUsername\Documents\CyberForensics
   ```

### Step 2: Verify Project Files

Check that you have these key files:
```cmd
dir
```

You should see:
- `docker-compose.yml`
- `Dockerfile`
- `requirements.txt`
- `README.md`
- `tools\` directory
- `web\` directory

---

## Building the Docker Containers

### Build All Services

**In PowerShell or Command Prompt:**

```cmd
docker-compose build
```

**What This Does:**
- Downloads base Python 3.11 image (~200MB)
- Installs all required Python packages
- Sets up the forensics tools and web portal
- Creates nginx web server for reports

**Build Time:** 3-5 minutes (first time only)

**Expected Output:**
```
[+] Building 156.2s (15/15) FINISHED
 => [internal] load build definition
 => [internal] load .dockerignore
 => [internal] load metadata for docker.io/library/python:3.11-slim
 => [1/10] FROM docker.io/library/python:3.11-slim
 => [2/10] WORKDIR /app
 => [3/10] COPY requirements.txt .
 => [4/10] RUN pip install --no-cache-dir -r requirements.txt
 ...
Successfully tagged cyberforensics:latest
```

---

## Running the Toolkit

### Start All Services

**Start in Background (Detached Mode):**
```cmd
docker-compose up -d
```

**Start with Logs Visible:**
```cmd
docker-compose up
```

**Expected Output:**
```
[+] Running 3/3
 ✔ Container cyberforensics_web_interface  Started
 ✔ Container cyberforensics_web_portal     Started
 ✔ Container cyberforensics                Started
```

### Verify Services Are Running

```cmd
docker-compose ps
```

**Expected Output:**
```
NAME                          STATUS    PORTS
cyberforensics                Up
cyberforensics_web_interface  Up        0.0.0.0:8080->80/tcp
cyberforensics_web_portal     Up        0.0.0.0:5000->5000/tcp
```

All services should show **"Up"** status.

---

## Accessing the Tools

### Web Portal (Main Interface)

**URL:** http://localhost:5000

**What You'll See:**
- Professional dashboard with 8 tool modules
- Quick Actions for IP lookup and hash cracking
- Navigation sidebar
- Interactive statistics

**Available Tools:**
1. **File Forensics** - Recover deleted files, analyze metadata
2. **Network Analysis** - PCAP analysis, traffic monitoring
3. **Malware Analysis** - Static analysis, signature detection
4. **Password Recovery** - Hash cracking with AI assistance
5. **Social Media OSINT** - Profile analysis, cross-platform correlation
6. **Geolocation** - IP tracking with interactive maps
7. **Email Forensics** - Header analysis, sender tracking
8. **User Attribution** - Evidence correlation, attacker identification

### Reports Viewer

**URL:** http://localhost:8080/reports

**What You'll See:**
- All generated forensic reports
- Download links
- Timestamps

### Command Line Interface (Advanced)

**Run CLI Commands Inside Container:**

```cmd
docker-compose exec forensics python cli/main.py --help
```

**Example Commands:**

**IP Analysis:**
```cmd
docker-compose exec forensics python cli/main.py geolocation ip-analysis --ip 8.8.8.8 --output reports/ip_analysis.html --generate-map
```

**Hash Cracking:**
```cmd
docker-compose exec forensics python cli/main.py password hash-crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --attack dictionary
```

**PCAP Analysis:**
```cmd
docker-compose exec forensics python cli/main.py network analyze-pcap --pcap data/captures/traffic.pcap --output reports/network_analysis.html
```

**Malware Analysis:**
```cmd
docker-compose exec forensics python cli/main.py malware static-analysis --file data/samples/suspicious.exe --output reports/malware_report.json
```

**Email Forensics:**
```cmd
docker-compose exec forensics python cli/main.py email-forensics --email data/emails/phishing.eml --trace --generate-map --output reports/email_analysis.html
```

---

## Stopping the Toolkit

### Stop All Services

**Stop and Remove Containers:**
```cmd
docker-compose down
```

**Stop Without Removing:**
```cmd
docker-compose stop
```

### Restart Services

**Restart All:**
```cmd
docker-compose restart
```

**Restart Specific Service:**
```cmd
docker-compose restart web_portal
```

---

## Troubleshooting

### Issue: "Docker daemon is not running"

**Solution:**
1. Open **Docker Desktop** from Start Menu
2. Wait for whale icon in system tray to turn green
3. Try command again

### Issue: "Port 5000 already in use"

**Solution:**
1. Find process using port:
   ```cmd
   netstat -ano | findstr :5000
   ```
2. Kill the process or change port in `docker-compose.yml`:
   ```yaml
   ports:
     - "5001:5000"  # Changed from 5000:5000
   ```
3. Restart: `docker-compose up -d`

### Issue: "Cannot connect to Docker daemon"

**Solution:**
1. Ensure virtualization is enabled in BIOS
2. Restart Docker Desktop
3. Restart your computer
4. Check Windows Features:
   - Open "Turn Windows features on or off"
   - Enable "Virtual Machine Platform"
   - Enable "Windows Subsystem for Linux"

### Issue: Container keeps restarting

**Check Logs:**
```cmd
docker-compose logs web_portal
```

**Common Fixes:**
1. Rebuild containers:
   ```cmd
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

### Issue: Web portal shows blank page

**Solutions:**
1. Check container is running:
   ```cmd
   docker-compose ps
   ```
2. Check logs:
   ```cmd
   docker-compose logs web_portal
   ```
3. Clear browser cache and refresh
4. Try different browser
5. Check firewall isn't blocking port 5000

### Issue: "Access denied" when running commands

**Solution:**
Run PowerShell or Command Prompt as **Administrator**

### Issue: Slow performance

**Solutions:**
1. Increase Docker memory allocation (Settings → Resources)
2. Close other applications
3. Ensure Docker is using WSL 2 backend (Settings → General)

---

## Advanced Usage

### Copy Files Into Container

**Copy evidence files to analyze:**
```cmd
docker cp C:\Users\YourName\Downloads\evidence.pcap cyberforensics:/app/data/captures/
```

**Copy malware sample:**
```cmd
docker cp C:\Users\YourName\Downloads\suspicious.exe cyberforensics:/app/data/samples/
```

### Copy Reports Out of Container

**Copy specific report:**
```cmd
docker cp cyberforensics:/app/reports/analysis.html C:\Users\YourName\Desktop\
```

**Copy all reports:**
```cmd
docker cp cyberforensics:/app/reports/ C:\Users\YourName\Desktop\forensics_reports\
```

### View Live Logs

**All services:**
```cmd
docker-compose logs -f
```

**Specific service:**
```cmd
docker-compose logs -f web_portal
```

Press `Ctrl+C` to exit logs.

### Access Container Shell

**Interactive bash shell:**
```cmd
docker-compose exec forensics bash
```

**Run commands inside:**
```bash
cd /app
ls -la
python cli/main.py --help
exit
```

### Update the Toolkit

**After pulling new code:**
```cmd
git pull
docker-compose down
docker-compose build
docker-compose up -d
```

### Clean Up Old Images

**Remove unused Docker data:**
```cmd
docker system prune -a
```

**Warning:** This removes all unused containers, images, and networks.

---

## Quick Start Summary

### First Time Setup:
```cmd
# 1. Navigate to project
cd C:\Users\YourUsername\Documents\CyberForensics

# 2. Build containers
docker-compose build

# 3. Start services
docker-compose up -d

# 4. Open browser
start http://localhost:5000
```

### Daily Use:
```cmd
# Start
docker-compose up -d

# Use web interface
start http://localhost:5000

# Stop when done
docker-compose down
```

### Quick Commands:
```cmd
# Status
docker-compose ps

# Logs
docker-compose logs -f

# Restart
docker-compose restart

# Rebuild
docker-compose build --no-cache
```

---

## Getting Help

### Check Service Status
```cmd
docker-compose ps
docker-compose logs
```

### Test Docker Installation
```cmd
docker run hello-world
```

### Docker Desktop Troubleshooting
1. Right-click Docker icon in system tray
2. Select "Troubleshoot"
3. Click "Reset to factory defaults" (last resort)

---

## Security Notes

1. **Malware Analysis:** The toolkit analyzes malware statically (without execution). Still, use caution with unknown files.

2. **Network Access:** Tools may make external connections for:
   - IP geolocation lookups
   - Email header analysis
   - Social media OSINT

3. **Firewall:** Windows Firewall may prompt for Docker access - click "Allow"

4. **Passwords:** Hash cracking tools are for **authorized forensic investigations only**

5. **Data Privacy:** All analysis happens locally in Docker containers. No data is sent to external servers except for geolocation API calls.

---

## System Resource Usage

**Typical Resource Usage:**
- **Memory:** 2-4GB RAM
- **CPU:** 2-4 cores during analysis
- **Disk:** ~2GB for images, ~500MB per investigation
- **Network:** Minimal (only for geolocation lookups)

**Monitor Resources:**
- Docker Desktop → Dashboard → Containers
- Task Manager → Performance

---

## Next Steps

1. ✅ Install Docker Desktop
2. ✅ Build the containers
3. ✅ Start the services
4. ✅ Access web portal at http://localhost:5000
5. ✅ Try Quick Actions on dashboard
6. ✅ Explore the 8 forensic tools
7. ✅ Review reports at http://localhost:8080/reports

**Happy Investigating!** 🔍

For issues or questions, check the logs with `docker-compose logs -f`
