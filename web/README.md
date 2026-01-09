# CyberForensics Web Portal

Professional browser-based interface for the CyberForensics Toolkit.

## Features

### Main Dashboard
- **Statistics Overview**: Total tools, reports, and system status
- **Tool Cards**: Quick access to all 8 forensics modules
- **Quick Actions**: Instant IP lookup and hash cracking
- **Recent Activity**: Track your forensic investigations

### Available Modules

1. **File Forensics**
   - File recovery from disk images
   - Metadata extraction and analysis
   - Timeline generation

2. **Network Analysis**
   - PCAP file analysis
   - Live traffic monitoring
   - Intrusion detection

3. **Malware Analysis**
   - Static analysis without execution
   - Signature-based detection
   - Risk assessment

4. **Password Recovery**
   - Multi-algorithm hash cracking
   - Dictionary attacks
   - AI-assisted smart attacks

5. **OSINT**
   - Social media intelligence
   - Profile analysis
   - Activity tracking

6. **IP Geolocation** 🌍
   - Interactive world map
   - IP address geolocation
   - Network traceroute
   - Real-time visualization

7. **Email Forensics**
   - Header analysis
   - Sender tracking
   - Spoofing detection

8. **Attribution Engine**
   - Evidence correlation
   - Suspect identification
   - Attack timeline

## Access

### Start the Web Portal

```bash
docker-compose up -d web_portal
```

### Access URLs

- **Web Portal**: http://localhost:5000
- **Reports Server**: http://localhost:8080

## Usage

### Quick IP Lookup

1. Go to Dashboard (http://localhost:5000)
2. Enter IP address in "Quick IP Lookup" section
3. Click "Analyze"
4. View instant results with geolocation

### Interactive Geolocation

1. Navigate to "IP Geolocation" from sidebar
2. Enter IP address or traceroute destination
3. View results on interactive world map
4. Click markers for detailed information
5. Zoom and pan the map

### Generate Reports

1. Use any forensics tool
2. Results saved to `/data/reports`
3. View reports at http://localhost:8080/reports

## API Endpoints

The web portal provides REST API endpoints:

### IP Analysis
```bash
POST /api/analyze-ip
Content-Type: application/json

{
  "ip": "8.8.8.8"
}
```

### Traceroute
```bash
POST /api/traceroute
Content-Type: application/json

{
  "destination": "example.com"
}
```

### Hash Cracking
```bash
POST /api/hash-crack
Content-Type: application/json

{
  "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "algorithm": "md5",
  "method": "smart"
}
```

### System Status
```bash
GET /api/status
```

## Development

### Run Locally

```bash
cd web
export FLASK_APP=app.py
export FLASK_ENV=development
python app.py
```

### File Structure

```
web/
├── app.py                 # Flask application
├── templates/             # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Dashboard
│   ├── geolocation.html  # Geolocation tool
│   ├── reports.html      # Reports viewer
│   └── ...               # Other tools
├── static/               # Static files
│   ├── css/             # Stylesheets
│   ├── js/              # JavaScript
│   └── img/             # Images
└── README.md            # This file
```

## Features in Detail

### Interactive Map
- Powered by Leaflet.js and OpenStreetMap
- Real-time marker placement
- Color-coded risk levels
- Traceroute path visualization
- Clickable popups with details
- Zoom from world to street level

### Professional UI
- Responsive Bootstrap design
- Gradient theme
- Animated transitions
- Toast notifications
- Loading spinners
- Real-time updates

### Security
- Input validation
- Error handling
- Secure file handling
- CORS protection

## Troubleshooting

### Port Already in Use

If port 5000 is already in use, change it in `docker-compose.yml`:

```yaml
ports:
  - "5001:5000"  # Change 5001 to any available port
```

### Web Portal Not Loading

1. Check container status:
```bash
docker-compose ps
```

2. View logs:
```bash
docker-compose logs web_portal
```

3. Restart service:
```bash
docker-compose restart web_portal
```

## Browser Compatibility

- Chrome/Edge: ✅ Full support
- Firefox: ✅ Full support
- Safari: ✅ Full support
- Opera: ✅ Full support

## Technologies Used

- **Backend**: Flask 3.0, Python 3.11
- **Frontend**: Bootstrap 5, jQuery 3.7
- **Maps**: Leaflet.js 1.9
- **Icons**: Font Awesome 6.4
- **Data**: JSON REST API
