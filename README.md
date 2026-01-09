# CyberForensics Toolkit

A comprehensive Digital Forensics and Cybersecurity Investigation Suite for analyzing cyber attacks, fraud, malicious software, and conducting social media intelligence gathering.

## 🛠️ Tools Included

### 1. Digital Forensics Suite
- **File Recovery Tool**: Recover deleted files from disk images and storage devices
- **Metadata Analyzer**: Extract and analyze file metadata (EXIF, timestamps, file signatures)
- **Timeline Generator**: Create forensic timelines from file system artifacts

### 2. Network Analysis Tools
- **Packet Analyzer**: Capture and analyze network traffic (similar to Wireshark)
- **Traffic Monitor**: Real-time network monitoring and suspicious activity detection
- **Protocol Analyzer**: Deep packet inspection for various protocols

### 3. Malware Analysis Tools
- **Static Analyzer**: Analyze malware without execution (strings, PE headers, entropy)
- **Signature Detector**: Detect malicious patterns using YARA-like rules
- **Behavioral Analysis**: Identify suspicious code patterns and API calls

### 4. Password Recovery Tools
- **Hash Cracker**: Recover passwords from various hash formats (MD5, SHA, bcrypt)
- **Dictionary Attack**: Use wordlists for password recovery
- **Rainbow Table Support**: Fast password recovery using precomputed hashes

### 5. Social Media Intelligence (OSINT)
- **Profile Analyzer**: Gather public information from social media profiles
- **Activity Tracker**: Monitor and analyze user activities across platforms
- **Network Mapping**: Visualize social network connections

### 6. IP Geolocation & Tracking 🆕
- **IP Intelligence**: Geolocate IP addresses with precise coordinates, ISP identification, and reputation scoring
- **Traceroute Analyzer**: Hop-by-hop network path analysis with complete geolocation
- **Interactive World Map**: Beautiful, zoomable map visualization showing traveled paths
- **Route Visualization**: Visual tracking from hop to hop with detailed information at each location
- **Geographic Analysis**: Compare locations, calculate distances, detect anomalies

### 7. Email Forensics 🆕
- **Email Intelligence**: Deep analysis of email headers, authentication (SPF/DKIM/DMARC), attachments
- **Sender Geolocation**: Trace email path through mail servers with geographic coordinates
- **Interactive Route Maps**: Visualize complete email journey on interactive world map
- **Spoofing Detection**: Advanced detection of sender spoofing and phishing attempts
- **Path Analysis**: Identify suspicious mail server routes and anomalies

## 🚀 Quick Start with Docker

### Prerequisites
- Docker Desktop for Windows
- At least 4GB RAM available for containers
- 10GB free disk space

### Installation

1. Clone this repository:
```bash
git clone https://github.com/madcrx/CyberForensics.git
cd CyberForensics
```

2. Build the Docker container:
```bash
docker-compose build
```

3. Run the forensics toolkit:
```bash
docker-compose up -d
```

### 🌐 Web Portal (Recommended!)

**Access the professional browser interface:**

```bash
# Open in your browser:
http://localhost:5000
```

**Features:**
- 🎯 **Interactive Dashboard** with all 8 tools
- 🗺️ **Interactive World Maps** for IP tracking
- 📊 **Real-time Visualizations**
- 🔍 **Quick Actions** for instant analysis
- 📈 **Statistics & Reports**

### 💻 Command Line Interface

4. Access the CLI:
```bash
docker-compose exec forensics python cli/main.py --help
```

## 📖 Usage Examples

### Web Portal (Easy!)

1. Open browser to http://localhost:5000
2. Click any tool card on the dashboard
3. Enter your data and click "Analyze"
4. View results instantly with visual maps

### Command Line Interface

### File Recovery
```bash
docker-compose exec forensics python cli/main.py file-recovery --source /data/disk.img --output /data/recovered
```

### Network Analysis
```bash
docker-compose exec forensics python cli/main.py network-analyze --pcap /data/capture.pcap --report /data/report.html
```

### Malware Analysis
```bash
docker-compose exec forensics python cli/main.py malware-scan --file /data/suspicious.exe --verbose
```

### Password Cracking
```bash
docker-compose exec forensics python cli/main.py hash-crack --hash "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist /data/wordlists/common.txt
```

### Social Media OSINT
```bash
docker-compose exec forensics python cli/main.py osint-gather --username "target_user" --platform twitter --output /data/osint_report.json
```

### IP Geolocation & Tracking
```bash
# Analyze IP with geolocation
docker-compose exec forensics python cli/main.py geolocation ip-analysis --ip 8.8.8.8 --output /data/ip_report.html

# Traceroute with interactive map
docker-compose exec forensics python cli/main.py geolocation traceroute --destination example.com --generate-map --output /data/route_report.txt

# Generate interactive world map
docker-compose exec forensics python cli/main.py geolocation generate-map --data /data/geo_data.json --output /data/world_map.html
```

### Email Forensics
```bash
# Analyze email with sender tracking
docker-compose exec forensics python cli/main.py email-forensics --email /data/suspicious.eml --trace --generate-map --output /data/email_report.txt
```

## 🔒 Legal Notice

**IMPORTANT**: This toolkit is designed for:
- Authorized security testing and penetration testing
- Digital forensics investigations by law enforcement
- Incident response and defensive security
- Educational purposes and security research
- CTF competitions and training

**You must have explicit authorization before using these tools on any systems, networks, or data that you do not own or have permission to test.**

Unauthorized access to computer systems, networks, or data is illegal. Always ensure you have proper authorization and operate within legal boundaries.

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [Tool Reference](docs/TOOLS.md)

## 🛡️ Features

- ✅ Fully containerized with Docker
- ✅ Cross-platform support (Windows, Linux, macOS)
- ✅ Command-line interface for automation
- ✅ Comprehensive logging and reporting
- ✅ Modular architecture for easy extension
- ✅ Support for industry-standard file formats

## 🤝 Contributing

Contributions are welcome! Please ensure all contributions are for legitimate security research and defensive purposes.

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

The authors and contributors of this toolkit are not responsible for any misuse or damage caused by this software. Use at your own risk and always comply with applicable laws and regulations.
