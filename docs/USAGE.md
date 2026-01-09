# Usage Guide

## Overview

The CyberForensics Toolkit provides a comprehensive command-line interface for digital forensics investigations. All tools are accessed through the main CLI:

```bash
python cli/main.py <module> <action> [options]
```

## Available Modules

### 1. File Forensics (`file-forensics`)

#### File Recovery

Recover deleted files from disk images:

```bash
python cli/main.py file-forensics recover \
    --image /data/evidence/disk.img \
    --output /data/recovered \
    --report /data/reports/recovery_report.txt
```

#### Metadata Analysis

Extract metadata from files:

```bash
# Single file
python cli/main.py file-forensics metadata \
    --file /data/evidence/document.pdf \
    --output /data/reports/metadata.json \
    --format json

# Directory (recursive)
python cli/main.py file-forensics metadata \
    --directory /data/evidence \
    --recursive \
    --output /data/reports/metadata_report.json \
    --timeline /data/reports/timeline.txt
```

### 2. Network Analysis (`network`)

#### PCAP Analysis

Analyze network packet captures:

```bash
python cli/main.py network analyze-pcap \
    --pcap /data/evidence/capture.pcap \
    --output /data/reports/network_analysis.html \
    --format html
```

Features:
- Protocol distribution analysis
- Suspicious activity detection
- Source/destination IP tracking
- Port scanning detection
- DNS tunneling identification

#### Live Traffic Monitoring

Monitor live network traffic:

```bash
python cli/main.py network monitor \
    --interface eth0 \
    --duration 300 \
    --live \
    --output /data/reports/traffic_stats.json
```

### 3. Malware Analysis (`malware`)

#### Static Analysis

Analyze malware without execution:

```bash
# Single file
python cli/main.py malware static-analysis \
    --file /data/samples/suspicious.exe \
    --output /data/reports/malware_report.txt

# Directory scan
python cli/main.py malware static-analysis \
    --directory /data/samples \
    --recursive \
    --output /data/reports/malware_scan.json \
    --format json
```

#### Signature-Based Detection

Scan files using signature rules:

```bash
python cli/main.py malware signature-scan \
    --file /data/samples/malware.exe \
    --rules /data/signatures/custom_rules.json \
    --output /data/reports/detection_report.txt
```

### 4. Password Recovery (`password`)

#### Hash Cracking

**Dictionary Attack:**
```bash
python cli/main.py password crack-hash \
    --hash "5f4dcc3b5aa765d61d8327deb882cf99" \
    --algorithm md5 \
    --wordlist /data/wordlists/rockyou.txt \
    --output /data/reports/cracked.txt \
    --workers 8
```

**AI-Assisted Smart Attack:**
```bash
python cli/main.py password crack-hash \
    --hash "e10adc3949ba59abbe56e057f20f883e" \
    --algorithm md5 \
    --smart \
    --username john.doe \
    --output /data/reports/cracked.txt
```

**Brute Force:**
```bash
python cli/main.py password crack-hash \
    --hash "5d41402abc4b2a76b9719d911017c592" \
    --algorithm md5 \
    --bruteforce \
    --max-length 6 \
    --output /data/reports/cracked.txt
```

#### Password Dump Analysis

Analyze leaked password databases:

```bash
python cli/main.py password analyze-dump \
    --dump /data/evidence/passwords.txt \
    --format-type "user:pass" \
    --output /data/reports/password_analysis.txt \
    --wordlist /data/wordlists/generated.txt
```

### 5. Social Media OSINT (`osint`)

#### Profile Analysis

Investigate user across social media platforms:

```bash
python cli/main.py osint profile-analysis \
    --username target_user \
    --platforms twitter facebook instagram linkedin \
    --output /data/reports/osint_profile.html \
    --format html
```

#### Activity Tracking

Analyze user activity patterns:

```bash
python cli/main.py osint activity-tracking \
    --activities /data/evidence/user_activities.json \
    --output /data/reports/activity_analysis.txt
```

### 6. User Attribution (`attribution`)

#### Attack Attribution

Correlate evidence to identify attackers:

```bash
python cli/main.py attribution \
    --network-evidence /data/evidence/network_data.json \
    --file-evidence /data/evidence/file_metadata.json \
    --social-evidence /data/evidence/social_profiles.json \
    --output /data/reports/attribution_report.txt \
    --le-export /data/reports/law_enforcement_package.json
```

This generates:
- Comprehensive attribution report
- Suspect identification with confidence scores
- Attack timeline
- Evidence correlation
- Law enforcement-ready evidence package

## Common Workflows

### Investigating a Cyber Attack

1. **Capture Network Evidence**
```bash
python cli/main.py network monitor --interface eth0 --duration 3600 \
    --output /data/evidence/network_capture.json
```

2. **Analyze Malicious Files**
```bash
python cli/main.py malware static-analysis --directory /data/samples \
    --recursive --output /data/evidence/malware_analysis.json
```

3. **Gather OSINT**
```bash
python cli/main.py osint profile-analysis --username suspect123 \
    --platforms twitter github --output /data/evidence/osint.json
```

4. **Attribute Attack**
```bash
python cli/main.py attribution \
    --network-evidence /data/evidence/network_capture.json \
    --file-evidence /data/evidence/malware_analysis.json \
    --social-evidence /data/evidence/osint.json \
    --output /data/reports/FINAL_ATTRIBUTION_REPORT.txt \
    --le-export /data/reports/evidence_package.json
```

### Password Breach Investigation

1. **Analyze Leaked Database**
```bash
python cli/main.py password analyze-dump \
    --dump /data/evidence/leaked_passwords.txt \
    --output /data/reports/breach_analysis.txt \
    --wordlist /data/wordlists/common_patterns.txt
```

2. **Crack Sample Hashes**
```bash
python cli/main.py password crack-hash \
    --hash "..." \
    --algorithm sha256 \
    --smart \
    --output /data/reports/cracked_samples.txt
```

### Malware Analysis Workflow

1. **Static Analysis**
```bash
python cli/main.py malware static-analysis \
    --file /data/samples/malware.exe \
    --output /data/reports/static_analysis.json
```

2. **Signature Detection**
```bash
python cli/main.py malware signature-scan \
    --file /data/samples/malware.exe \
    --output /data/reports/signatures_detected.txt
```

3. **Extract Indicators**
   - Review reports for IP addresses, domains, file hashes
   - Use for threat intelligence and IOC sharing

## Tips and Best Practices

### Performance Optimization

- Use `--workers` parameter for parallel processing in password cracking
- Enable recursive scanning only when necessary
- Use JSON format for large datasets, text for readability

### Evidence Handling

- Always work on copies of evidence, never originals
- Document the chain of custody for all evidence
- Use hash verification before and after analysis
- Store evidence securely with proper access controls

### Report Generation

- Use HTML format for interactive reports with visualizations
- Use JSON format for programmatic access and data processing
- Use text format for quick review and documentation

### Privacy and Legal Considerations

- Ensure proper authorization before investigating any system
- Follow local laws and regulations regarding digital forensics
- Document all actions and maintain detailed investigation logs
- Use law enforcement export feature for official investigations

## Web Interface

Access generated reports through the web interface:

```
http://localhost:8080/reports/
```

The web interface provides:
- Browse generated reports
- Interactive visualizations
- Timeline views
- Export capabilities

## Getting Help

For module-specific help:
```bash
python cli/main.py <module> --help
```

For general help:
```bash
python cli/main.py --help
```
