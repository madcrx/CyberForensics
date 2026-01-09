# CyberForensics Toolkit - System Architecture

## Overview

The CyberForensics Toolkit is a containerized, modular digital forensics platform designed for investigating cyber attacks, fraud, malware, and conducting OSINT operations.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Windows Host PC                              │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Docker Desktop                               │ │
│  │                                                                  │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │              Docker Compose Network                       │  │ │
│  │  │                                                            │  │ │
│  │  │  ┌──────────────────┐  ┌──────────────────┐             │  │ │
│  │  │  │  Web Portal      │  │  Web Interface   │             │  │ │
│  │  │  │  (Flask)         │  │  (Nginx)         │             │  │ │
│  │  │  │  Port: 5000      │  │  Port: 8080      │             │  │ │
│  │  │  └────────┬─────────┘  └────────┬─────────┘             │  │ │
│  │  │           │                     │                        │  │ │
│  │  │           └──────────┬──────────┘                        │  │ │
│  │  │                      │                                   │  │ │
│  │  │           ┌──────────▼──────────────────────┐           │  │ │
│  │  │           │  Forensics Container            │           │  │ │
│  │  │           │  (Python 3.11)                  │           │  │ │
│  │  │           │                                 │           │  │ │
│  │  │           │  ┌──────────────────────────┐  │           │  │ │
│  │  │           │  │   CLI Interface          │  │           │  │ │
│  │  │           │  │   (cli/main.py)          │  │           │  │ │
│  │  │           │  └──────────────────────────┘  │           │  │ │
│  │  │           │                                 │           │  │ │
│  │  │           │  ┌──────────────────────────┐  │           │  │ │
│  │  │           │  │   8 Forensics Modules    │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 1. File Forensics        │  │           │  │ │
│  │  │           │  │    - File Recovery       │  │           │  │ │
│  │  │           │  │    - Metadata Analysis   │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 2. Network Analysis      │  │           │  │ │
│  │  │           │  │    - Packet Analyzer     │  │           │  │ │
│  │  │           │  │    - Traffic Monitor     │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 3. Malware Analysis      │  │           │  │ │
│  │  │           │  │    - Static Analyzer     │  │           │  │ │
│  │  │           │  │    - Signature Detector  │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 4. Password Recovery     │  │           │  │ │
│  │  │           │  │    - Hash Cracker        │  │           │  │ │
│  │  │           │  │    - Password Analyzer   │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 5. Social Media OSINT    │  │           │  │ │
│  │  │           │  │    - Profile Analyzer    │  │           │  │ │
│  │  │           │  │    - Activity Tracker    │  │           │  │ │
│  │  │           │  │    - Network Mapper      │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 6. Geolocation           │  │           │  │ │
│  │  │           │  │    - IP Intelligence     │  │           │  │ │
│  │  │           │  │    - Traceroute Analyzer │  │           │  │ │
│  │  │           │  │    - Map Generator       │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 7. Email Forensics       │  │           │  │ │
│  │  │           │  │    - Email Intelligence  │  │           │  │ │
│  │  │           │  │    - Header Analysis     │  │           │  │ │
│  │  │           │  ├──────────────────────────┤  │           │  │ │
│  │  │           │  │ 8. User Attribution      │  │           │  │ │
│  │  │           │  │    - Attribution Engine  │  │           │  │ │
│  │  │           │  │    - Digital Fingerprint │  │           │  │ │
│  │  │           │  └──────────────────────────┘  │           │  │ │
│  │  │           │                                 │           │  │ │
│  │  │           │  ┌──────────────────────────┐  │           │  │ │
│  │  │           │  │   Data Directories       │  │           │  │ │
│  │  │           │  │   /app/data/             │  │           │  │ │
│  │  │           │  │   /app/reports/          │  │           │  │ │
│  │  │           │  └──────────────────────────┘  │           │  │ │
│  │  │           └─────────────────────────────────┘           │  │ │
│  │  │                                                          │  │ │
│  │  └──────────────────────────────────────────────────────────┘  │ │
│  │                                                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  Browser Access:                                                     │
│  http://localhost:5000 → Web Portal                                 │
│  http://localhost:8080 → Reports Viewer                             │
└───────────────────────────────────────────────────────────────────────┘

        ▲                           │
        │                           ▼
   User Input              External Services (Optional)
                          ┌────────────────────────┐
                          │ IP Geolocation APIs    │
                          │ OSINT Data Sources     │
                          │ Threat Intelligence    │
                          └────────────────────────┘
```

---

## Component Details

### 1. Docker Compose Orchestration

**File:** `docker-compose.yml`

**Services:**
- **forensics**: Main CLI container with all tools
- **web_portal**: Flask web application (port 5000)
- **web_interface**: Nginx server for reports (port 8080)

**Volumes:**
- `./tools` → `/app/tools` (forensics modules)
- `./data` → `/app/data` (evidence files)
- `./reports` → `/app/reports` (generated reports)
- `./web` → `/app/web` (web portal files)

**Network:**
- Bridge network connecting all containers
- Port forwarding: 5000 (Flask), 8080 (Nginx)

---

### 2. Web Portal (Flask Application)

**Location:** `web/app.py`

**Technology Stack:**
- **Backend:** Flask 3.0 (Python)
- **Frontend:** Bootstrap 5, jQuery 3.7, Leaflet.js 1.9
- **Styling:** Custom CSS with gradient theme
- **Icons:** Font Awesome 6.4

**Features:**
- REST API endpoints for all tools
- Real-time AJAX operations
- Interactive dashboards
- File upload handling
- Report generation and viewing

**API Endpoints:**
```
POST   /api/analyze-ip       - IP geolocation analysis
POST   /api/traceroute       - Network path tracing
POST   /api/analyze-email    - Email forensics
POST   /api/hash-crack       - Password hash cracking
POST   /api/analyze-file     - File forensics
POST   /api/analyze-network  - PCAP analysis
POST   /api/analyze-malware  - Malware analysis
POST   /api/osint-search     - Social media OSINT
GET    /api/status           - System status
```

**Templates:**
- `base.html` - Base layout with navigation
- `index.html` - Main dashboard
- `geolocation.html` - Interactive maps
- `email_forensics.html` - Email analysis
- `file_forensics.html` - File recovery
- `network_analysis.html` - Network tools
- `malware_analysis.html` - Malware tools
- `password_recovery.html` - Hash cracking
- `osint.html` - Social media intelligence
- `attribution.html` - User attribution
- `reports.html` - Report viewer

---

### 3. CLI Interface

**Location:** `cli/main.py`

**Commands:**
```
cyberforensics file-forensics    - File recovery and metadata
cyberforensics network           - Network packet analysis
cyberforensics malware           - Malware analysis
cyberforensics password          - Password recovery
cyberforensics osint             - Social media intelligence
cyberforensics geolocation       - IP tracking and mapping
cyberforensics email-forensics   - Email header analysis
cyberforensics attribution       - Evidence correlation
```

**Usage Pattern:**
```bash
docker-compose exec forensics python cli/main.py [module] [action] [options]
```

---

### 4. Forensics Modules

#### File Forensics (`tools/file_forensics/`)
- **file_recovery.py**: Carves deleted files using signatures
- **metadata_analyzer.py**: Extracts EXIF, timestamps, document metadata

#### Network Analysis (`tools/network_analysis/`)
- **packet_analyzer.py**: PCAP parsing, anomaly detection
- **traffic_monitor.py**: Real-time traffic analysis

#### Malware Analysis (`tools/malware_analysis/`)
- **static_analyzer.py**: PE analysis, entropy, suspicious APIs
- **signature_detector.py**: YARA-like pattern matching

#### Password Recovery (`tools/password_recovery/`)
- **hash_cracker.py**: Multi-algorithm cracking (MD5, SHA, NTLM)
- **password_analyzer.py**: Pattern analysis, breach correlation

#### Social Media OSINT (`tools/social_media_osint/`)
- **profile_analyzer.py**: Cross-platform profile correlation
- **activity_tracker.py**: Behavioral pattern analysis
- **network_mapper.py**: Social network graph generation

#### Geolocation (`tools/geolocation/`)
- **ip_intelligence.py**: IP geolocation, reputation scoring
- **traceroute_analyzer.py**: Hop-by-hop path analysis
- **map_generator.py**: Interactive Leaflet.js maps

#### Email Forensics (`tools/email_forensics/`)
- **email_intelligence.py**: Header analysis, SPF/DKIM/DMARC validation

#### User Attribution (`tools/user_attribution/`)
- **attribution_engine.py**: Multi-source evidence correlation
- **digital_fingerprinting.py**: User identification tracking

---

### 5. Data Flow

#### Investigation Workflow:

```
1. Evidence Collection
   ↓
2. Evidence Upload (via Web or CLI)
   ↓
3. Tool Selection
   ↓
4. Analysis Execution
   ├─→ File Analysis
   ├─→ Network Analysis
   ├─→ Malware Analysis
   ├─→ OSINT Gathering
   ├─→ Geolocation Tracking
   └─→ Email Forensics
   ↓
5. Attribution Engine (correlates all evidence)
   ↓
6. Report Generation
   ├─→ HTML Reports
   ├─→ JSON Data
   ├─→ Interactive Maps
   └─→ Timeline Visualizations
   ↓
7. Report Viewing (http://localhost:8080/reports)
```

#### Example: IP Investigation Flow

```
User Input: IP Address (8.8.8.8)
   ↓
Web Portal → POST /api/analyze-ip
   ↓
Flask App → Call IPIntelligence.analyze_ip()
   ↓
IPIntelligence Module:
   ├─→ Geolocate IP (coordinates)
   ├─→ Lookup ISP information
   ├─→ Check reputation databases
   ├─→ Calculate risk score
   └─→ Return JSON result
   ↓
Flask App → Return JSON to frontend
   ↓
JavaScript:
   ├─→ Display result in table
   ├─→ Add marker to Leaflet map
   └─→ Show popup with details
   ↓
User sees: Interactive map with IP location
```

---

### 6. Security Architecture

#### Isolation:
- All tools run inside Docker containers
- No direct host filesystem access
- Network isolation between containers

#### Data Protection:
- Evidence files stored in mounted volumes
- Reports generated in separate directory
- No external data transmission (except geolocation APIs)

#### Malware Handling:
- Static analysis only (no code execution)
- Sandboxed environment
- Safe string extraction and pattern matching

---

### 7. Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11 |
| Web Framework | Flask 3.0 |
| Frontend | Bootstrap 5, jQuery 3.7 |
| Mapping | Leaflet.js 1.9 |
| Containerization | Docker, Docker Compose |
| Web Server | Nginx (for reports) |
| Database | File-based (JSON, CSV) |
| Network Analysis | Scapy, dpkt |
| File Carving | Custom signature matching |
| Hash Algorithms | hashlib, bcrypt |

---

### 8. File Structure

```
CyberForensics/
├── cli/
│   └── main.py                      # CLI interface
├── tools/
│   ├── file_forensics/
│   │   ├── file_recovery.py
│   │   └── metadata_analyzer.py
│   ├── network_analysis/
│   │   ├── packet_analyzer.py
│   │   └── traffic_monitor.py
│   ├── malware_analysis/
│   │   ├── static_analyzer.py
│   │   └── signature_detector.py
│   ├── password_recovery/
│   │   ├── hash_cracker.py
│   │   └── password_analyzer.py
│   ├── social_media_osint/
│   │   ├── profile_analyzer.py
│   │   ├── activity_tracker.py
│   │   └── network_mapper.py
│   ├── geolocation/
│   │   ├── ip_intelligence.py
│   │   ├── traceroute_analyzer.py
│   │   └── map_generator.py
│   ├── email_forensics/
│   │   └── email_intelligence.py
│   └── user_attribution/
│       ├── attribution_engine.py
│       └── digital_fingerprinting.py
├── web/
│   ├── app.py                       # Flask application
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── geolocation.html
│   │   ├── email_forensics.html
│   │   └── ... (other tool pages)
│   └── static/
│       ├── css/
│       ├── js/
│       └── images/
├── data/
│   ├── captures/                    # PCAP files
│   ├── samples/                     # Malware samples
│   ├── emails/                      # Email files
│   └── wordlists/                   # Password lists
├── reports/                         # Generated reports
├── docker-compose.yml               # Container orchestration
├── Dockerfile                       # Container build
├── requirements.txt                 # Python dependencies
├── README.md                        # Main documentation
├── DEPLOYMENT_WINDOWS.md            # Windows deployment guide
├── QUICK_START_WINDOWS.md           # Quick start guide
├── ARCHITECTURE.md                  # This file
├── deploy_windows.bat               # Windows deployment script
└── stop_windows.bat                 # Stop script
```

---

### 9. Scalability Considerations

#### Current Design:
- Single-host Docker Compose deployment
- Suitable for individual investigators
- Handles moderate evidence volumes

#### Future Enhancements:
- **Multi-node Deployment**: Kubernetes orchestration
- **Distributed Processing**: Celery task queue for large files
- **Database Backend**: PostgreSQL for case management
- **Authentication**: Multi-user support with role-based access
- **API Gateway**: RESTful API for external integrations
- **Real-time Collaboration**: WebSocket for team investigations

---

### 10. Performance Characteristics

| Operation | Typical Time | Resource Usage |
|-----------|--------------|----------------|
| IP Geolocation | < 1 second | Low CPU, 10MB RAM |
| PCAP Analysis (1GB) | 2-5 minutes | High CPU, 500MB RAM |
| File Recovery (10GB) | 10-30 minutes | Medium CPU, 1GB RAM |
| Hash Cracking (dictionary) | 1-60 minutes | High CPU, 200MB RAM |
| Malware Static Analysis | 1-10 seconds | Low CPU, 100MB RAM |
| Email Forensics | < 5 seconds | Low CPU, 50MB RAM |
| OSINT Profile Search | 5-30 seconds | Low CPU, 100MB RAM |
| Attribution Correlation | 1-5 seconds | Medium CPU, 200MB RAM |

---

### 11. Integration Points

#### External APIs (Optional):
- **IP Geolocation**: MaxMind, IPInfo, ip-api.com
- **Threat Intelligence**: VirusTotal, AbuseIPDB
- **OSINT**: Social media APIs (Twitter, Facebook, LinkedIn)
- **Email Validation**: MXToolbox, DNS lookups

#### Export Formats:
- **Reports**: HTML, JSON, CSV
- **Maps**: HTML (Leaflet.js), GeoJSON
- **Evidence**: ZIP packages for law enforcement
- **Timelines**: JSON, CSV

---

## Deployment Models

### 1. Standalone (Current)
```
Windows PC → Docker Desktop → CyberForensics Toolkit
```

### 2. Client-Server (Future)
```
Multiple PCs → Load Balancer → CyberForensics Cluster
```

### 3. Cloud (Future)
```
Web Browser → Cloud Provider → Containerized Toolkit
```

---

## Summary

The CyberForensics Toolkit provides a comprehensive, modular, and containerized platform for digital forensics investigations. The architecture emphasizes:

1. **Modularity**: Each tool is independent and reusable
2. **Usability**: Both CLI and web interfaces
3. **Visualization**: Interactive maps and dashboards
4. **Integration**: Evidence correlation across tools
5. **Security**: Containerized, isolated execution
6. **Portability**: Runs on any Docker-capable system

The system is designed for ease of deployment on Windows PCs while maintaining professional-grade forensics capabilities.
