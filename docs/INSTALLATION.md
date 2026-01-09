# Installation Guide

## Prerequisites

- Docker Desktop for Windows (minimum version 20.10)
- At least 4GB RAM available
- 10GB free disk space
- Windows 10/11 with WSL2 enabled

## Quick Start Installation

### 1. Clone the Repository

```bash
git clone https://github.com/madcrx/CyberForensics.git
cd CyberForensics
```

### 2. Build Docker Container

```bash
docker-compose build
```

This will:
- Build the CyberForensics image with all dependencies
- Set up necessary volumes for data persistence
- Configure network settings for packet capture

### 3. Start the Container

```bash
docker-compose up -d
```

### 4. Access the Forensics Shell

```bash
docker-compose exec forensics /bin/bash
```

You're now inside the CyberForensics environment!

## Verify Installation

Test the installation by running:

```bash
python cli/main.py --help
```

You should see the CyberForensics banner and available modules.

## Configuration

### Data Directories

The following directories are automatically created and mounted:

- `/data/samples` - Store malware samples and suspicious files here
- `/data/evidence` - Place evidence files (PCAP, disk images, etc.)
- `/data/wordlists` - Password wordlists for cracking
- `/data/reports` - Generated reports are saved here
- `/data/output` - General output directory

### Network Capabilities

The container has `NET_RAW` and `NET_ADMIN` capabilities for:
- Packet capture
- Network monitoring
- Traffic analysis

## Updating

To update to the latest version:

```bash
git pull origin main
docker-compose build --no-cache
docker-compose up -d
```

## Troubleshooting

### Docker Build Fails

If the build fails, try:
```bash
docker system prune -a
docker-compose build --no-cache
```

### Permission Issues on Windows

Run Docker Desktop as Administrator and ensure WSL2 is properly configured.

### Network Capture Not Working

Ensure Docker has elevated privileges and network capabilities are enabled.

## Next Steps

- Read the [Usage Guide](USAGE.md)
- Review [Tool Reference](TOOLS.md)
- Check out [Example Workflows](EXAMPLES.md)
