"""
IP Intelligence Tool
Advanced IP address analysis with geolocation, ISP identification, and threat intelligence.
"""

import json
import socket
import struct
import ipaddress
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IPIntelligence:
    """
    Comprehensive IP intelligence and geolocation tool.
    Analyzes IP addresses, geolocates them, and provides threat intelligence.
    """

    def __init__(self):
        self.analyzed_ips = {}
        self.ip_database = self._load_ip_database()

    def _load_ip_database(self) -> Dict:
        """Load IP geolocation database (simulated)"""
        # In production, this would load from MaxMind GeoIP2, IP2Location, etc.
        # For now, we'll create a comprehensive database structure
        return {
            'geoip_ranges': self._initialize_geoip_data(),
            'isp_data': self._initialize_isp_data(),
            'threat_intel': self._initialize_threat_data(),
        }

    def _initialize_geoip_data(self) -> Dict:
        """Initialize geolocation IP ranges"""
        return {
            # Major cloud providers and common IP ranges
            '8.8.8.0/24': {
                'country': 'United States',
                'country_code': 'US',
                'region': 'California',
                'city': 'Mountain View',
                'latitude': 37.4056,
                'longitude': -122.0775,
                'timezone': 'America/Los_Angeles',
                'organization': 'Google LLC',
            },
            '1.1.1.0/24': {
                'country': 'United States',
                'country_code': 'US',
                'region': 'California',
                'city': 'San Francisco',
                'latitude': 37.7749,
                'longitude': -122.4194,
                'timezone': 'America/Los_Angeles',
                'organization': 'Cloudflare Inc.',
            },
            '13.107.0.0/16': {
                'country': 'United States',
                'country_code': 'US',
                'region': 'Washington',
                'city': 'Redmond',
                'latitude': 47.6739,
                'longitude': -122.1211,
                'timezone': 'America/Los_Angeles',
                'organization': 'Microsoft Corporation',
            },
            '52.0.0.0/8': {
                'country': 'United States',
                'country_code': 'US',
                'region': 'Virginia',
                'city': 'Ashburn',
                'latitude': 39.0438,
                'longitude': -77.4874,
                'timezone': 'America/New_York',
                'organization': 'Amazon Web Services',
            },
            '192.168.0.0/16': {
                'country': 'Private Network',
                'country_code': 'XX',
                'region': 'RFC1918',
                'city': 'Private',
                'latitude': 0.0,
                'longitude': 0.0,
                'timezone': 'UTC',
                'organization': 'Private Network',
            },
            '10.0.0.0/8': {
                'country': 'Private Network',
                'country_code': 'XX',
                'region': 'RFC1918',
                'city': 'Private',
                'latitude': 0.0,
                'longitude': 0.0,
                'timezone': 'UTC',
                'organization': 'Private Network',
            },
        }

    def _initialize_isp_data(self) -> Dict:
        """Initialize ISP/ASN data"""
        return {
            'AS15169': {'name': 'Google LLC', 'country': 'US'},
            'AS13335': {'name': 'Cloudflare Inc.', 'country': 'US'},
            'AS8075': {'name': 'Microsoft Corporation', 'country': 'US'},
            'AS16509': {'name': 'Amazon.com Inc.', 'country': 'US'},
            'AS701': {'name': 'Verizon Business', 'country': 'US'},
            'AS7922': {'name': 'Comcast Cable Communications', 'country': 'US'},
        }

    def _initialize_threat_data(self) -> Dict:
        """Initialize threat intelligence data"""
        return {
            'malicious_ips': set(),
            'tor_exit_nodes': set(),
            'proxy_servers': set(),
            'vpn_servers': set(),
            'known_scanners': set(),
        }

    def _get_default_geolocation(self) -> Dict:
        """Return default geolocation data when lookup fails"""
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'region': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'timezone': 'UTC',
            'organization': 'Unknown',
        }

    def _get_default_isp_info(self) -> Dict:
        """Return default ISP info when lookup fails"""
        return {
            'asn': 'Unknown',
            'isp_name': 'Unknown',
            'organization': 'Unknown',
            'network_type': 'Unknown',
        }

    def _get_default_threat_intel(self) -> Dict:
        """Return default threat intelligence when check fails"""
        return {
            'is_malicious': False,
            'is_tor_exit': False,
            'is_proxy': False,
            'is_vpn': False,
            'is_scanner': False,
            'blacklists': [],
            'threat_categories': [],
        }

    def analyze_ip(self, ip_address: str) -> Dict:
        """
        Comprehensive IP address analysis.

        Args:
            ip_address: IP address to analyze

        Returns:
            Dictionary with complete IP intelligence
        """
        logger.info(f"Analyzing IP: {ip_address}")

        # Validate input
        if not ip_address or not isinstance(ip_address, str):
            logger.error(f"Invalid IP address input: {ip_address}")
            return {'error': f'Invalid IP address: {ip_address}'}

        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())

            # Get sub-analyses with error handling
            reverse_dns = None
            geolocation = {}
            isp_info = {}
            threat_intelligence = {}

            try:
                reverse_dns = self._reverse_dns_lookup(ip_address)
            except Exception as e:
                logger.warning(f"Reverse DNS lookup failed: {e}")

            try:
                geolocation = self._geolocate_ip(ip_address)
                if not isinstance(geolocation, dict):
                    geolocation = {}
            except Exception as e:
                logger.error(f"Geolocation failed: {e}")
                geolocation = self._get_default_geolocation()

            try:
                isp_info = self._get_isp_info(ip_address)
                if not isinstance(isp_info, dict):
                    isp_info = {}
            except Exception as e:
                logger.warning(f"ISP info lookup failed: {e}")
                isp_info = self._get_default_isp_info()

            try:
                threat_intelligence = self._check_threat_intel(ip_address)
                if not isinstance(threat_intelligence, dict):
                    threat_intelligence = {}
            except Exception as e:
                logger.warning(f"Threat intelligence check failed: {e}")
                threat_intelligence = self._get_default_threat_intel()

            analysis = {
                'ip_address': str(ip_address),
                'ip_version': int(ip_obj.version),
                'is_private': bool(ip_obj.is_private),
                'is_loopback': bool(ip_obj.is_loopback),
                'is_multicast': bool(ip_obj.is_multicast),
                'is_reserved': bool(ip_obj.is_reserved),
                'reverse_dns': reverse_dns,
                'geolocation': geolocation,
                'isp_info': isp_info,
                'threat_intelligence': threat_intelligence,
                'reputation_score': 0,
                'risk_level': 'UNKNOWN',
            }

            # Calculate reputation score
            try:
                analysis['reputation_score'] = self._calculate_reputation(analysis)
                analysis['risk_level'] = self._assess_risk_level(analysis['reputation_score'])
            except Exception as e:
                logger.warning(f"Reputation calculation failed: {e}")
                analysis['reputation_score'] = 50
                analysis['risk_level'] = 'UNKNOWN'

            self.analyzed_ips[ip_address] = analysis
            return analysis

        except ValueError as e:
            logger.error(f"Invalid IP address: {e}")
            return {'error': f'Invalid IP address: {ip_address}'}
        except Exception as e:
            logger.error(f"Unexpected error analyzing IP {ip_address}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': f'Analysis failed: {str(e)}'}

    def _reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def _geolocate_ip(self, ip_address: str) -> Dict:
        """
        Geolocate IP address.

        Returns:
            Geolocation data including coordinates
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)

            # Check against known ranges
            for network_str, geo_data in self.ip_database['geoip_ranges'].items():
                network = ipaddress.ip_network(network_str)
                if ip_obj in network:
                    return geo_data

            # Default/unknown location
            return self._estimate_location_from_ip(ip_address)

        except Exception as e:
            logger.error(f"Geolocation error: {e}")
            return {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0.0,
                'longitude': 0.0,
                'timezone': 'UTC',
            }

    def _estimate_location_from_ip(self, ip_address: str) -> Dict:
        """
        Estimate location from IP address using heuristics.
        In production, use MaxMind GeoIP2 or similar.
        """
        # Parse IP octets for estimation
        octets = ip_address.split('.')

        # Simple heuristic based on regional IP allocation
        first_octet = int(octets[0])

        locations = {
            range(1, 37): ('United States', 'US', 39.0, -77.0, 'America/New_York'),
            range(37, 50): ('United States', 'US', 37.0, -122.0, 'America/Los_Angeles'),
            range(50, 80): ('Europe', 'EU', 51.5, -0.1, 'Europe/London'),
            range(80, 120): ('Asia', 'AS', 35.6, 139.7, 'Asia/Tokyo'),
            range(120, 150): ('Asia Pacific', 'AP', 1.3, 103.8, 'Asia/Singapore'),
            range(150, 180): ('Australia', 'AU', -33.9, 151.2, 'Australia/Sydney'),
            range(180, 223): ('Asia', 'AS', 31.2, 121.5, 'Asia/Shanghai'),
        }

        for ip_range, (country, code, lat, lon, tz) in locations.items():
            if first_octet in ip_range:
                return {
                    'country': country,
                    'country_code': code,
                    'region': 'Unknown',
                    'city': 'Unknown',
                    'latitude': lat,
                    'longitude': lon,
                    'timezone': tz,
                    'organization': 'Unknown',
                    'estimated': True,
                }

        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'timezone': 'UTC',
            'estimated': True,
        }

    def _get_isp_info(self, ip_address: str) -> Dict:
        """Get ISP/ASN information"""
        # In production, query WHOIS or use ASN databases
        return {
            'asn': 'AS????',
            'isp_name': 'Unknown ISP',
            'organization': 'Unknown',
            'network_type': self._classify_network(ip_address),
        }

    def _classify_network(self, ip_address: str) -> str:
        """Classify network type"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)

            if ip_obj.is_private:
                return 'Private Network'
            elif ip_obj.is_loopback:
                return 'Loopback'
            elif ip_obj.is_multicast:
                return 'Multicast'

            # Check if cloud provider
            first_octet = int(ip_address.split('.')[0])
            if first_octet in [52, 54]:
                return 'Cloud Provider (AWS)'
            elif first_octet == 13:
                return 'Cloud Provider (Azure)'
            elif first_octet in [8, 35]:
                return 'Cloud Provider (Google)'

            return 'Public Internet'

        except:
            return 'Unknown'

    def _check_threat_intel(self, ip_address: str) -> Dict:
        """Check IP against threat intelligence databases"""
        threats = {
            'is_malicious': False,
            'is_tor_exit': False,
            'is_proxy': False,
            'is_vpn': False,
            'is_scanner': False,
            'blacklists': [],
            'threat_categories': [],
        }

        # Check against known threats
        if ip_address in self.ip_database['threat_intel']['malicious_ips']:
            threats['is_malicious'] = True
            threats['threat_categories'].append('Known Malicious')

        if ip_address in self.ip_database['threat_intel']['tor_exit_nodes']:
            threats['is_tor_exit'] = True
            threats['threat_categories'].append('Tor Exit Node')

        if ip_address in self.ip_database['threat_intel']['vpn_servers']:
            threats['is_vpn'] = True
            threats['threat_categories'].append('VPN Server')

        return threats

    def _calculate_reputation(self, analysis: Dict) -> int:
        """
        Calculate IP reputation score (0-100, higher is better).

        Returns:
            Reputation score
        """
        score = 50  # Start neutral

        # Negative factors
        threat = analysis.get('threat_intelligence', {})
        if threat.get('is_malicious'):
            score -= 40
        if threat.get('is_tor_exit'):
            score -= 20
        if threat.get('is_proxy'):
            score -= 10
        if threat.get('is_vpn'):
            score -= 5

        # Positive factors
        if analysis.get('reverse_dns'):
            score += 10

        geo = analysis.get('geolocation', {})
        if geo.get('organization') and 'Unknown' not in geo.get('organization', ''):
            score += 10

        return max(0, min(100, score))

    def _assess_risk_level(self, reputation_score: int) -> str:
        """Assess risk level based on reputation"""
        if reputation_score >= 70:
            return 'LOW'
        elif reputation_score >= 50:
            return 'MEDIUM'
        elif reputation_score >= 30:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def batch_analyze(self, ip_list: List[str]) -> List[Dict]:
        """
        Analyze multiple IP addresses.

        Args:
            ip_list: List of IP addresses

        Returns:
            List of analysis results
        """
        results = []
        for ip in ip_list:
            result = self.analyze_ip(ip)
            results.append(result)

        return results

    def compare_ip_locations(self, ip_addresses: List[str]) -> Dict:
        """
        Compare geographic locations of multiple IPs.

        Args:
            ip_addresses: List of IPs to compare

        Returns:
            Comparison analysis
        """
        locations = []

        for ip in ip_addresses:
            analysis = self.analyze_ip(ip)
            geo = analysis.get('geolocation', {})

            if geo.get('latitude') and geo.get('longitude'):
                locations.append({
                    'ip': ip,
                    'country': geo.get('country'),
                    'city': geo.get('city'),
                    'latitude': geo.get('latitude'),
                    'longitude': geo.get('longitude'),
                })

        # Calculate geographic spread
        if len(locations) >= 2:
            distances = []
            for i in range(len(locations)):
                for j in range(i + 1, len(locations)):
                    dist = self._calculate_distance(
                        locations[i]['latitude'],
                        locations[i]['longitude'],
                        locations[j]['latitude'],
                        locations[j]['longitude']
                    )
                    distances.append(dist)

            return {
                'locations': locations,
                'unique_countries': len(set(loc['country'] for loc in locations)),
                'unique_cities': len(set(loc['city'] for loc in locations)),
                'max_distance_km': max(distances) if distances else 0,
                'avg_distance_km': sum(distances) / len(distances) if distances else 0,
                'geographic_spread': 'HIGH' if max(distances) > 5000 else 'MEDIUM' if max(distances) > 1000 else 'LOW',
            }

        return {'locations': locations}

    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate distance between two coordinates using Haversine formula.

        Returns:
            Distance in kilometers
        """
        from math import radians, sin, cos, sqrt, atan2

        R = 6371  # Earth's radius in km

        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))

        return R * c

    def generate_report(self, output_path: str, format: str = 'json') -> None:
        """
        Generate IP intelligence report.

        Args:
            output_path: Path to save report
            format: Report format (json or text)
        """
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump({
                    'generated': datetime.now().isoformat(),
                    'total_ips_analyzed': len(self.analyzed_ips),
                    'ips': list(self.analyzed_ips.values()),
                }, f, indent=2, default=str)

        else:
            with open(output_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("IP INTELLIGENCE REPORT\n")
                f.write("=" * 80 + "\n\n")

                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total IPs Analyzed: {len(self.analyzed_ips)}\n\n")

                for ip, analysis in self.analyzed_ips.items():
                    f.write(f"IP Address: {ip}\n")
                    f.write("-" * 80 + "\n")

                    geo = analysis.get('geolocation', {})
                    f.write(f"Location: {geo.get('city')}, {geo.get('region')}, {geo.get('country')}\n")
                    f.write(f"Coordinates: {geo.get('latitude')}, {geo.get('longitude')}\n")
                    f.write(f"Organization: {geo.get('organization', 'Unknown')}\n")

                    isp = analysis.get('isp_info', {})
                    f.write(f"ISP: {isp.get('isp_name', 'Unknown')}\n")
                    f.write(f"Network Type: {isp.get('network_type', 'Unknown')}\n")

                    f.write(f"Reputation Score: {analysis.get('reputation_score')}/100\n")
                    f.write(f"Risk Level: {analysis.get('risk_level')}\n")

                    if analysis.get('reverse_dns'):
                        f.write(f"Reverse DNS: {analysis['reverse_dns']}\n")

                    threat = analysis.get('threat_intelligence', {})
                    if threat.get('threat_categories'):
                        f.write(f"Threats: {', '.join(threat['threat_categories'])}\n")

                    f.write("\n")

        logger.info(f"Report saved to {output_path}")


def main():
    """Example usage of IPIntelligence"""
    import argparse

    parser = argparse.ArgumentParser(description='IP Intelligence Tool')
    parser.add_argument('--ip', help='Single IP to analyze')
    parser.add_argument('--ip-list', help='File with list of IPs')
    parser.add_argument('--compare', nargs='+', help='Compare multiple IPs')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--format', choices=['json', 'text'], default='text', help='Report format')

    args = parser.parse_args()

    intel = IPIntelligence()

    if args.ip:
        result = intel.analyze_ip(args.ip)
        print(f"\n📍 IP Intelligence for {args.ip}")
        print(f"  Location: {result['geolocation']['city']}, {result['geolocation']['country']}")
        print(f"  Coordinates: {result['geolocation']['latitude']}, {result['geolocation']['longitude']}")
        print(f"  Reputation: {result['reputation_score']}/100")
        print(f"  Risk Level: {result['risk_level']}")

    elif args.ip_list:
        with open(args.ip_list, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        intel.batch_analyze(ips)

    elif args.compare:
        comparison = intel.compare_ip_locations(args.compare)
        print(f"\n🌍 Geographic Analysis")
        print(f"  Unique Countries: {comparison['unique_countries']}")
        print(f"  Max Distance: {comparison['max_distance_km']:.0f} km")
        print(f"  Geographic Spread: {comparison['geographic_spread']}")

    intel.generate_report(args.output, args.format)
    print(f"\n✓ Report saved to: {args.output}")


if __name__ == '__main__':
    main()
