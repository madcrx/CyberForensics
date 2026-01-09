"""
Interactive Map Generator
Creates interactive zoomable world maps showing IP locations and network paths.
"""

import json
from typing import Dict, List
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class InteractiveMapGenerator:
    """
    Generate interactive HTML maps with IP locations and traceroute paths.
    Uses Leaflet.js for beautiful, zoomable world map visualizations.
    """

    def __init__(self):
        self.markers = []
        self.routes = []

    def add_ip_marker(self, ip_data: Dict) -> None:
        """
        Add IP location marker to map.

        Args:
            ip_data: IP intelligence data with geolocation
        """
        geo = ip_data.get('geolocation', {})

        if geo.get('latitude') and geo.get('longitude'):
            marker = {
                'ip': ip_data.get('ip_address'),
                'latitude': geo['latitude'],
                'longitude': geo['longitude'],
                'city': geo.get('city', 'Unknown'),
                'country': geo.get('country', 'Unknown'),
                'organization': geo.get('organization', 'Unknown'),
                'risk_level': ip_data.get('risk_level', 'UNKNOWN'),
                'reputation': ip_data.get('reputation_score', 0),
                'popup_content': self._generate_popup_content(ip_data),
            }

            self.markers.append(marker)

    def add_traceroute_path(self, route_hops: List[Dict], destination: str = None) -> None:
        """
        Add traceroute path to map.

        Args:
            route_hops: List of hop dictionaries with geolocation
            destination: Destination label
        """
        path_coordinates = []
        hop_markers = []

        for hop in route_hops:
            coord = hop.get('coordinates', {})
            if coord.get('latitude') and coord.get('longitude'):
                path_coordinates.append([
                    coord['latitude'],
                    coord['longitude']
                ])

                # Create marker for this hop
                geo = hop.get('geolocation', {})
                hop_markers.append({
                    'hop_number': hop['hop_number'],
                    'ip': hop['ip_address'],
                    'latitude': coord['latitude'],
                    'longitude': coord['longitude'],
                    'city': geo.get('city', 'Unknown'),
                    'country': geo.get('country', 'Unknown'),
                    'rtt': hop.get('rtt'),
                    'popup_content': self._generate_hop_popup(hop),
                })

        route = {
            'destination': destination or 'Unknown',
            'coordinates': path_coordinates,
            'hops': hop_markers,
            'total_hops': len(route_hops),
        }

        self.routes.append(route)

    def _generate_popup_content(self, ip_data: Dict) -> str:
        """Generate HTML content for IP marker popup"""
        geo = ip_data.get('geolocation', {})
        threat = ip_data.get('threat_intelligence', {})

        html = f"""
        <div class="ip-popup">
            <h3>{ip_data.get('ip_address')}</h3>
            <table>
                <tr><td><strong>Location:</strong></td><td>{geo.get('city')}, {geo.get('country')}</td></tr>
                <tr><td><strong>Coordinates:</strong></td><td>{geo.get('latitude')}, {geo.get('longitude')}</td></tr>
                <tr><td><strong>Organization:</strong></td><td>{geo.get('organization', 'Unknown')}</td></tr>
                <tr><td><strong>Reputation:</strong></td><td>{ip_data.get('reputation_score')}/100</td></tr>
                <tr><td><strong>Risk Level:</strong></td><td><span class="risk-{ip_data.get('risk_level', 'unknown').lower()}">{ip_data.get('risk_level')}</span></td></tr>
        """

        if threat.get('threat_categories'):
            html += f"<tr><td><strong>Threats:</strong></td><td>{', '.join(threat['threat_categories'])}</td></tr>"

        if ip_data.get('reverse_dns'):
            html += f"<tr><td><strong>Hostname:</strong></td><td>{ip_data['reverse_dns']}</td></tr>"

        html += """
            </table>
        </div>
        """

        return html

    def _generate_hop_popup(self, hop: Dict) -> str:
        """Generate HTML content for traceroute hop popup"""
        geo = hop.get('geolocation', {})
        isp = hop.get('isp_info', {})

        html = f"""
        <div class="hop-popup">
            <h3>Hop {hop['hop_number']}</h3>
            <table>
                <tr><td><strong>IP Address:</strong></td><td>{hop['ip_address']}</td></tr>
                <tr><td><strong>Location:</strong></td><td>{geo.get('city')}, {geo.get('country')}</td></tr>
                <tr><td><strong>ISP:</strong></td><td>{isp.get('isp_name', 'Unknown')}</td></tr>
        """

        if hop.get('rtt'):
            html += f"<tr><td><strong>RTT:</strong></td><td>{hop['rtt']} ms</td></tr>"

        html += """
            </table>
        </div>
        """

        return html

    def generate_map(self, output_path: str, title: str = "IP Geolocation Map") -> None:
        """
        Generate interactive HTML map.

        Args:
            output_path: Path to save HTML map
            title: Map title
        """
        logger.info(f"Generating interactive map: {title}")

        html = self._create_html_template(title)

        with open(output_path, 'w') as f:
            f.write(html)

        logger.info(f"Interactive map saved to {output_path}")

    def _create_html_template(self, title: str) -> str:
        """Create complete HTML map template"""
        markers_json = json.dumps(self.markers)
        routes_json = json.dumps(self.routes)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- Leaflet CSS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />

    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
        }}

        #map {{
            position: absolute;
            top: 60px;
            bottom: 0;
            width: 100%;
        }}

        .header {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .header h1 {{
            margin: 0;
            font-size: 24px;
            font-weight: 300;
        }}

        .stats {{
            display: flex;
            gap: 30px;
            font-size: 14px;
        }}

        .stat {{
            text-align: center;
        }}

        .stat-number {{
            font-size: 20px;
            font-weight: bold;
        }}

        .stat-label {{
            font-size: 11px;
            opacity: 0.8;
        }}

        .ip-popup, .hop-popup {{
            min-width: 250px;
        }}

        .ip-popup h3, .hop-popup h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
            font-size: 16px;
        }}

        .ip-popup table, .hop-popup table {{
            width: 100%;
            font-size: 13px;
        }}

        .ip-popup td, .hop-popup td {{
            padding: 3px 5px;
        }}

        .risk-low {{ color: #22c55e; font-weight: bold; }}
        .risk-medium {{ color: #eab308; font-weight: bold; }}
        .risk-high {{ color: #f97316; font-weight: bold; }}
        .risk-critical {{ color: #ef4444; font-weight: bold; }}

        .legend {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            z-index: 1000;
        }}

        .legend h4 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #333;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
            font-size: 12px;
        }}

        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }}

        .loading {{
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            z-index: 2000;
            text-align: center;
        }}

        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }}

        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🌍 {title}</h1>
        <div class="stats">
            <div class="stat">
                <div class="stat-number" id="marker-count">0</div>
                <div class="stat-label">IP LOCATIONS</div>
            </div>
            <div class="stat">
                <div class="stat-number" id="route-count">0</div>
                <div class="stat-label">ROUTES</div>
            </div>
            <div class="stat">
                <div class="stat-number" id="hop-count">0</div>
                <div class="stat-label">HOPS</div>
            </div>
        </div>
    </div>

    <div id="map"></div>

    <div class="legend">
        <h4>Risk Levels</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: #22c55e;"></div>
            <span>Low Risk</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #eab308;"></div>
            <span>Medium Risk</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #f97316;"></div>
            <span>High Risk</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #ef4444;"></div>
            <span>Critical Risk</span>
        </div>
    </div>

    <div class="loading" id="loading">
        <div class="spinner"></div>
        <div>Loading map...</div>
    </div>

    <!-- Leaflet JavaScript -->
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

    <script>
        // Initialize map
        var map = L.map('map').setView([20, 0], 2);

        // Add tile layer
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18,
        }}).addTo(map);

        // Risk level colors
        var riskColors = {{
            'LOW': '#22c55e',
            'MEDIUM': '#eab308',
            'HIGH': '#f97316',
            'CRITICAL': '#ef4444',
            'UNKNOWN': '#6b7280'
        }};

        // Load markers
        var markers = {markers_json};
        var routes = {routes_json};

        // Add IP markers
        markers.forEach(function(marker) {{
            var color = riskColors[marker.risk_level] || riskColors.UNKNOWN;

            var circle = L.circleMarker([marker.latitude, marker.longitude], {{
                radius: 8,
                fillColor: color,
                color: '#fff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.8
            }}).addTo(map);

            circle.bindPopup(marker.popup_content);

            // Add tooltip
            circle.bindTooltip(marker.ip + '<br>' + marker.city, {{
                permanent: false,
                direction: 'top'
            }});
        }});

        // Add routes
        var totalHops = 0;
        routes.forEach(function(route) {{
            // Draw polyline
            var polyline = L.polyline(route.coordinates, {{
                color: '#667eea',
                weight: 3,
                opacity: 0.7,
                smoothFactor: 1
            }}).addTo(map);

            // Add animated marker moving along path
            var pathDecorator = L.polylineDecorator(polyline, {{
                patterns: [
                    {{
                        offset: '0%',
                        repeat: '10%',
                        symbol: L.Symbol.arrowHead({{
                            pixelSize: 8,
                            polygon: false,
                            pathOptions: {{ stroke: true, color: '#764ba2', weight: 2 }}
                        }})
                    }}
                ]
            }}).addTo(map);

            // Add hop markers
            route.hops.forEach(function(hop) {{
                var hopMarker = L.marker([hop.latitude, hop.longitude], {{
                    icon: L.divIcon({{
                        className: 'hop-marker',
                        html: '<div style="background: #764ba2; color: white; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; border: 2px solid white;">' + hop.hop_number + '</div>',
                        iconSize: [24, 24]
                    }})
                }}).addTo(map);

                hopMarker.bindPopup(hop.popup_content);

                totalHops++;
            }});

            // Fit map to route bounds
            map.fitBounds(polyline.getBounds());
        }});

        // Update statistics
        document.getElementById('marker-count').textContent = markers.length;
        document.getElementById('route-count').textContent = routes.length;
        document.getElementById('hop-count').textContent = totalHops;

        // Hide loading
        setTimeout(function() {{
            document.getElementById('loading').style.display = 'none';
        }}, 500);

        // Add polyline decorator plugin
        (function() {{
            L.PolylineDecorator = L.FeatureGroup.extend({{
                options: {{
                    patterns: []
                }},

                initialize: function(paths, options) {{
                    L.FeatureGroup.prototype.initialize.call(this);
                    L.Util.setOptions(this, options);
                    this._paths = paths;
                    this._initDecoration();
                }},

                _initDecoration: function() {{
                    // Simplified decorator for arrows
                }}
            }});

            L.polylineDecorator = function(paths, options) {{
                return new L.PolylineDecorator(paths, options);
            }};
        }})();
    </script>
</body>
</html>
"""

        return html


def main():
    """Example usage of InteractiveMapGenerator"""
    import argparse

    parser = argparse.ArgumentParser(description='Interactive Map Generator')
    parser.add_argument('--data', required=True, help='JSON file with IP/route data')
    parser.add_argument('--output', required=True, help='Output HTML map file')
    parser.add_argument('--title', default='IP Geolocation Map', help='Map title')

    args = parser.parse_args()

    # Load data
    with open(args.data, 'r') as f:
        data = json.load(f)

    generator = InteractiveMapGenerator()

    # Add markers
    for ip_data in data.get('ips', []):
        generator.add_ip_marker(ip_data)

    # Add routes
    for route in data.get('routes', []):
        generator.add_traceroute_path(route.get('hops', []), route.get('destination'))

    # Generate map
    generator.generate_map(args.output, args.title)

    print(f"\n✓ Interactive map generated: {args.output}")
    print(f"  Open in browser to view visualization")


if __name__ == '__main__':
    main()
