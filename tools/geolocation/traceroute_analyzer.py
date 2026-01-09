"""
Traceroute Analyzer
Analyzes network paths and creates hop-by-hop geographic visualizations.
"""

import subprocess
import re
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TracerouteAnalyzer:
    """
    Analyze network paths using traceroute and geolocate each hop.
    Creates visualizations of network paths across the globe.
    """

    def __init__(self):
        self.routes = []
        self.hop_database = {}

    def trace_route(self, destination: str, max_hops: int = 30) -> List[Dict]:
        """
        Perform traceroute to destination and analyze each hop.

        Args:
            destination: Target IP or hostname
            max_hops: Maximum number of hops

        Returns:
            List of hop information with geolocation
        """
        logger.info(f"Tracing route to {destination}")

        hops = self._execute_traceroute(destination, max_hops)

        # Geolocate each hop
        from .ip_intelligence import IPIntelligence
        ip_intel = IPIntelligence()

        analyzed_hops = []
        for hop_num, hop_data in enumerate(hops, 1):
            # Safely get IP address
            ip_addr = hop_data.get('ip') if isinstance(hop_data, dict) else None

            if ip_addr:
                try:
                    analysis = ip_intel.analyze_ip(ip_addr)

                    # Skip if analysis returned an error
                    if not analysis or 'error' in analysis:
                        error_msg = analysis.get('error', 'Unknown error') if analysis else 'No analysis data'
                        logger.warning(f"Skipping hop {hop_num} ({ip_addr}) due to analysis error: {error_msg}")
                        continue

                    # Safely extract geolocation with defaults
                    geolocation = analysis.get('geolocation', {}) if isinstance(analysis.get('geolocation'), dict) else {}
                    isp_info = analysis.get('isp_info', {}) if isinstance(analysis.get('isp_info'), dict) else {}

                    # Ensure all geolocation fields are JSON-serializable
                    safe_geolocation = {
                        'country': str(geolocation.get('country', 'Unknown')) if geolocation.get('country') else 'Unknown',
                        'country_code': str(geolocation.get('country_code', 'XX')) if geolocation.get('country_code') else 'XX',
                        'region': str(geolocation.get('region', 'Unknown')) if geolocation.get('region') else 'Unknown',
                        'city': str(geolocation.get('city', 'Unknown')) if geolocation.get('city') else 'Unknown',
                        'latitude': float(geolocation.get('latitude', 0.0)) if geolocation.get('latitude') is not None else 0.0,
                        'longitude': float(geolocation.get('longitude', 0.0)) if geolocation.get('longitude') is not None else 0.0,
                        'timezone': str(geolocation.get('timezone', 'UTC')) if geolocation.get('timezone') else 'UTC',
                        'organization': str(geolocation.get('organization', 'Unknown')) if geolocation.get('organization') else 'Unknown',
                    }

                    # Ensure ISP info is JSON-serializable
                    safe_isp_info = {
                        'asn': str(isp_info.get('asn', 'Unknown')) if isp_info.get('asn') else 'Unknown',
                        'isp_name': str(isp_info.get('isp_name', 'Unknown')) if isp_info.get('isp_name') else 'Unknown',
                        'organization': str(isp_info.get('organization', 'Unknown')) if isp_info.get('organization') else 'Unknown',
                        'network_type': str(isp_info.get('network_type', 'Unknown')) if isp_info.get('network_type') else 'Unknown',
                    }

                    # Safely get RTT
                    rtt_value = hop_data.get('rtt')
                    safe_rtt = float(rtt_value) if rtt_value is not None and str(rtt_value).replace('.', '').isdigit() else None

                    analyzed_hop = {
                        'hop_number': int(hop_num),
                        'ip_address': str(ip_addr),
                        'hostname': str(hop_data.get('hostname')) if hop_data.get('hostname') else None,
                        'rtt': safe_rtt,
                        'geolocation': safe_geolocation,
                        'isp_info': safe_isp_info,
                        'coordinates': {
                            'latitude': safe_geolocation['latitude'],
                            'longitude': safe_geolocation['longitude'],
                        }
                    }

                    analyzed_hops.append(analyzed_hop)
                    self.hop_database[ip_addr] = analyzed_hop

                except Exception as e:
                    logger.error(f"Error analyzing hop {hop_num} ({ip_addr}): {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    continue
            else:
                logger.warning(f"Hop {hop_num} has no IP address, skipping")

        # Ensure we have valid data
        if not analyzed_hops:
            logger.warning(f"No valid hops found for destination {destination}")

        route_info = {
            'destination': str(destination),
            'timestamp': datetime.now().isoformat(),
            'total_hops': len(analyzed_hops),
            'hops': analyzed_hops,
        }

        self.routes.append(route_info)

        # Always return a list, even if empty
        return analyzed_hops if analyzed_hops else []

    def _execute_traceroute(self, destination: str, max_hops: int) -> List[Dict]:
        """
        Execute traceroute command and parse results.

        Returns:
            List of hop dictionaries
        """
        hops = []

        try:
            # Try traceroute command (Linux/Mac)
            try:
                result = subprocess.run(
                    ['traceroute', '-m', str(max_hops), '-n', destination],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                output = result.stdout
            except FileNotFoundError:
                # Try tracert on Windows
                result = subprocess.run(
                    ['tracert', '-h', str(max_hops), '-d', destination],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                output = result.stdout

            # Parse output
            hops = self._parse_traceroute_output(output)

        except subprocess.TimeoutExpired:
            logger.error("Traceroute timeout")
        except Exception as e:
            logger.error(f"Traceroute error: {e}")
            # Generate simulated route for demonstration
            hops = self._simulate_route(destination, max_hops)

        return hops

    def _parse_traceroute_output(self, output: str) -> List[Dict]:
        """Parse traceroute command output"""
        hops = []

        # Pattern for IP addresses and round-trip times
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        time_pattern = r'(\d+\.?\d*)\s*ms'

        for line in output.split('\n'):
            # Skip header lines
            if 'traceroute' in line.lower() or 'tracing' in line.lower():
                continue

            # Find IP address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(0)

                # Find RTT (first occurrence)
                time_match = re.search(time_pattern, line)
                rtt = float(time_match.group(1)) if time_match else None

                hops.append({
                    'ip': ip,
                    'hostname': None,  # Could extract from output if available
                    'rtt': rtt,
                })

        return hops

    def _simulate_route(self, destination: str, max_hops: int) -> List[Dict]:
        """
        Simulate a traceroute for demonstration purposes.
        In production, this would use real traceroute.
        """
        logger.info("Simulating traceroute (real traceroute not available)")

        # Simulate typical Internet route with geographic diversity
        simulated_hops = [
            {'ip': '192.168.1.1', 'rtt': 1.2},       # Local router
            {'ip': '10.0.0.1', 'rtt': 5.3},          # ISP gateway
            {'ip': '8.8.8.8', 'rtt': 15.7},          # Google DNS (Mountain View, CA)
            {'ip': '1.1.1.1', 'rtt': 25.4},          # Cloudflare (San Francisco, CA)
            {'ip': '13.107.4.50', 'rtt': 45.2},      # Microsoft (Redmond, WA)
            {'ip': '52.46.137.72', 'rtt': 65.8},     # AWS (Virginia)
        ]

        # Add destination
        try:
            import socket
            dest_ip = socket.gethostbyname(destination)
        except:
            dest_ip = destination

        simulated_hops.append({'ip': dest_ip, 'rtt': 85.3})

        return simulated_hops[:max_hops]

    def analyze_route_path(self, route_hops: List[Dict]) -> Dict:
        """
        Analyze the geographic path of a route.

        Args:
            route_hops: List of analyzed hops

        Returns:
            Path analysis
        """
        if not route_hops:
            return {}

        countries_visited = []
        total_distance = 0.0
        hop_distances = []

        for i in range(len(route_hops) - 1):
            current_hop = route_hops[i]
            next_hop = route_hops[i + 1]

            current_geo = current_hop.get('geolocation', {})
            next_geo = next_hop.get('geolocation', {})

            country = current_geo.get('country')
            if country and country not in countries_visited:
                countries_visited.append(country)

            # Calculate distance between hops
            if (current_geo.get('latitude') and current_geo.get('longitude') and
                next_geo.get('latitude') and next_geo.get('longitude')):

                from .ip_intelligence import IPIntelligence
                intel = IPIntelligence()

                distance = intel._calculate_distance(
                    current_geo['latitude'],
                    current_geo['longitude'],
                    next_geo['latitude'],
                    next_geo['longitude']
                )

                total_distance += distance
                hop_distances.append({
                    'from_hop': i + 1,
                    'to_hop': i + 2,
                    'distance_km': round(distance, 2),
                })

        return {
            'total_hops': len(route_hops),
            'countries_traversed': countries_visited,
            'num_countries': len(countries_visited),
            'total_distance_km': round(total_distance, 2),
            'hop_distances': hop_distances,
            'avg_hop_distance_km': round(total_distance / len(hop_distances), 2) if hop_distances else 0,
        }

    def compare_routes(self, destination1: str, destination2: str) -> Dict:
        """
        Compare routes to two different destinations.

        Args:
            destination1: First destination
            destination2: Second destination

        Returns:
            Comparison analysis
        """
        route1 = self.trace_route(destination1)
        route2 = self.trace_route(destination2)

        analysis1 = self.analyze_route_path(route1)
        analysis2 = self.analyze_route_path(route2)

        # Find common hops
        ips1 = set(hop['ip_address'] for hop in route1)
        ips2 = set(hop['ip_address'] for hop in route2)
        common_hops = ips1.intersection(ips2)

        return {
            'route1': {
                'destination': destination1,
                'analysis': analysis1,
            },
            'route2': {
                'destination': destination2,
                'analysis': analysis2,
            },
            'comparison': {
                'common_hops': list(common_hops),
                'num_common_hops': len(common_hops),
                'divergence_point': self._find_divergence_point(route1, route2),
            }
        }

    def _find_divergence_point(self, route1: List[Dict], route2: List[Dict]) -> Optional[int]:
        """Find the hop number where routes diverge"""
        for i in range(min(len(route1), len(route2))):
            if route1[i]['ip_address'] != route2[i]['ip_address']:
                return i + 1
        return None

    def detect_route_anomalies(self, route_hops: List[Dict]) -> List[Dict]:
        """
        Detect anomalies in network route.

        Args:
            route_hops: List of analyzed hops

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Check for geographic anomalies
        for i in range(len(route_hops) - 1):
            current = route_hops[i]
            next_hop = route_hops[i + 1]

            current_geo = current.get('geolocation', {})
            next_geo = next_hop.get('geolocation', {})

            # Anomaly: Large geographic jump
            if (current_geo.get('latitude') and next_geo.get('latitude')):
                from .ip_intelligence import IPIntelligence
                intel = IPIntelligence()

                distance = intel._calculate_distance(
                    current_geo['latitude'],
                    current_geo['longitude'],
                    next_geo['latitude'],
                    next_geo['longitude']
                )

                if distance > 3000:  # More than 3000km in one hop
                    anomalies.append({
                        'type': 'LARGE_GEOGRAPHIC_JUMP',
                        'severity': 'MEDIUM',
                        'hop': i + 1,
                        'description': f"Unusually large distance between hop {i+1} and {i+2}: {distance:.0f} km",
                        'from_location': f"{current_geo.get('city')}, {current_geo.get('country')}",
                        'to_location': f"{next_geo.get('city')}, {next_geo.get('country')}",
                    })

            # Anomaly: RTT inconsistency
            if current.get('rtt') and next_hop.get('rtt'):
                if next_hop['rtt'] < current['rtt']:
                    anomalies.append({
                        'type': 'RTT_DECREASE',
                        'severity': 'LOW',
                        'hop': i + 1,
                        'description': f"Round-trip time decreased (unusual)",
                    })

        # Check for route through high-risk countries
        high_risk_countries = ['North Korea', 'Iran', 'Syria']  # Example
        for i, hop in enumerate(route_hops, 1):
            country = hop.get('geolocation', {}).get('country')
            if country in high_risk_countries:
                anomalies.append({
                    'type': 'HIGH_RISK_COUNTRY',
                    'severity': 'HIGH',
                    'hop': i,
                    'description': f"Route passes through high-risk country: {country}",
                    'country': country,
                })

        return anomalies

    def generate_report(self, output_path: str) -> None:
        """Generate traceroute analysis report"""
        with open(output_path, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("TRACEROUTE ANALYSIS REPORT\n")
            f.write("=" * 100 + "\n\n")

            for route in self.routes:
                f.write(f"Destination: {route['destination']}\n")
                f.write(f"Timestamp: {route['timestamp']}\n")
                f.write(f"Total Hops: {route['total_hops']}\n")
                f.write("-" * 100 + "\n\n")

                for hop in route['hops']:
                    geo = hop.get('geolocation', {})
                    f.write(f"Hop {hop['hop_number']:2d}: {hop['ip_address']}\n")
                    f.write(f"         Location: {geo.get('city')}, {geo.get('country')}\n")
                    f.write(f"         Coordinates: {hop['coordinates']['latitude']}, {hop['coordinates']['longitude']}\n")
                    if hop.get('rtt'):
                        f.write(f"         RTT: {hop['rtt']} ms\n")
                    f.write(f"         ISP: {hop['isp_info'].get('isp_name', 'Unknown')}\n")
                    f.write("\n")

                # Path analysis
                analysis = self.analyze_route_path(route['hops'])
                f.write("\nPATH ANALYSIS:\n")
                f.write(f"  Countries Traversed: {', '.join(analysis.get('countries_traversed', []))}\n")
                f.write(f"  Total Distance: {analysis.get('total_distance_km', 0):.2f} km\n")
                f.write(f"  Average Hop Distance: {analysis.get('avg_hop_distance_km', 0):.2f} km\n")

                # Anomalies
                anomalies = self.detect_route_anomalies(route['hops'])
                if anomalies:
                    f.write("\nANOMALIES DETECTED:\n")
                    for anomaly in anomalies:
                        f.write(f"  [{anomaly['severity']}] {anomaly['description']}\n")

                f.write("\n" + "=" * 100 + "\n\n")

        logger.info(f"Report saved to {output_path}")


def main():
    """Example usage of TracerouteAnalyzer"""
    import argparse

    parser = argparse.ArgumentParser(description='Traceroute Analyzer')
    parser.add_argument('--destination', required=True, help='Target to trace')
    parser.add_argument('--max-hops', type=int, default=30, help='Maximum hops')
    parser.add_argument('--output', required=True, help='Output report path')

    args = parser.parse_args()

    analyzer = TracerouteAnalyzer()

    print(f"\n🌐 Tracing route to {args.destination}")
    hops = analyzer.trace_route(args.destination, args.max_hops)

    print(f"\n✓ Trace complete: {len(hops)} hops")

    # Analyze path
    analysis = analyzer.analyze_route_path(hops)
    print(f"  Countries: {analysis.get('num_countries')}")
    print(f"  Total Distance: {analysis.get('total_distance_km'):.0f} km")

    # Check for anomalies
    anomalies = analyzer.detect_route_anomalies(hops)
    if anomalies:
        print(f"  ⚠️ Anomalies: {len(anomalies)}")

    analyzer.generate_report(args.output)
    print(f"\n✓ Report saved to: {args.output}")


if __name__ == '__main__':
    main()
