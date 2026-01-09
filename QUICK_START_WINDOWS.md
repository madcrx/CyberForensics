# Quick Start Guide - Windows

## Ultra-Fast Deployment (2 Steps)

### Step 1: Install Docker Desktop

1. Download: [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Install and restart your computer
3. Start Docker Desktop (wait for green whale icon in system tray)

### Step 2: Run Deployment Script

**Option A: Automated (Easiest)**
1. Open the project folder
2. Double-click `deploy_windows.bat`
3. Wait 3-5 minutes
4. Browser opens automatically to http://localhost:5000

**Option B: Manual Commands**
```cmd
cd C:\Users\YourUsername\Documents\CyberForensics
docker-compose build
docker-compose up -d
start http://localhost:5000
```

## Access Points

- **Main Portal:** http://localhost:5000
- **Reports:** http://localhost:8080/reports

## Stop Services

Double-click `stop_windows.bat` or run:
```cmd
docker-compose down
```

## That's It!

See `DEPLOYMENT_WINDOWS.md` for detailed documentation.

---

## Troubleshooting One-Liners

**Docker not running?**
→ Start Docker Desktop from Start Menu

**Port already in use?**
→ `netstat -ano | findstr :5000` then kill process

**Build failed?**
→ `docker-compose build --no-cache`

**Can't access portal?**
→ Check: `docker-compose ps` (all should be "Up")

**Need logs?**
→ `docker-compose logs -f`

---

## Daily Workflow

```cmd
# Morning: Start toolkit
docker-compose up -d

# Work: Use web interface
start http://localhost:5000

# Evening: Stop toolkit
docker-compose down
```

## Update Toolkit

```cmd
git pull
docker-compose down
docker-compose build
docker-compose up -d
```

---

**You're ready to investigate!** 🔍
