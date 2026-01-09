"""
Packet Analyzer Tool
Captures and analyzes network packets for forensic investigation.
Similar to Wireshark functionality for network forensics.
"""

import struct
import socket
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict
import binascii

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """
    Network packet analyzer for forensic investigation.
    Captures and analyzes network traffic for suspicious activity.
    """

    def __init__(self):
        self.packets = []
        self.statistics = defaultdict(int)
        self.conversations = defaultdict(list)
        self.suspicious_activity = []

    def parse_pcap_file(self, pcap_path: str) -> List[Dict]:
        """
        Parse a PCAP file and extract packet information.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            List of parsed packet dictionaries
        """
        logger.info(f"Parsing PCAP file: {pcap_path}")

        try:
            with open(pcap_path, 'rb') as f:
                # Read PCAP global header
                global_header = f.read(24)
                if len(global_header) < 24:
                    logger.error("Invalid PCAP file")
                    return []

                magic_number = struct.unpack('I', global_header[:4])[0]

                # Check magic number for endianness
                if magic_number == 0xa1b2c3d4:
                    endian = '<'  # Little endian
                elif magic_number == 0xd4c3b2a1:
                    endian = '>'  # Big endian
                else:
                    logger.error("Invalid PCAP magic number")
                    return []

                # Read packets
                packet_count = 0
                while True:
                    packet = self._read_packet(f, endian)
                    if not packet:
                        break

                    packet_count += 1
                    packet['packet_number'] = packet_count
                    self.packets.append(packet)

                    # Update statistics
                    self._update_statistics(packet)

                logger.info(f"Parsed {packet_count} packets")
                return self.packets

        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            return []

    def _read_packet(self, f, endian: str) -> Optional[Dict]:
        """Read a single packet from PCAP file"""
        # Read packet header (16 bytes)
        packet_header = f.read(16)
        if len(packet_header) < 16:
            return None

        # Parse packet header
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f'{endian}IIII', packet_header
        )

        # Read packet data
        packet_data = f.read(incl_len)
        if len(packet_data) < incl_len:
            return None

        # Parse packet
        packet_info = {
            'timestamp': datetime.fromtimestamp(ts_sec + ts_usec / 1000000).isoformat(),
            'timestamp_unix': ts_sec + ts_usec / 1000000,
            'length': orig_len,
            'captured_length': incl_len,
        }

        # Parse Ethernet frame
        if incl_len >= 14:
            eth_info = self._parse_ethernet(packet_data)
            packet_info.update(eth_info)

        return packet_info

    def _parse_ethernet(self, data: bytes) -> Dict:
        """Parse Ethernet frame"""
        if len(data) < 14:
            return {}

        # Extract MAC addresses
        dst_mac = ':'.join(f'{b:02x}' for b in data[0:6])
        src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
        eth_type = struct.unpack('!H', data[12:14])[0]

        eth_info = {
            'dst_mac': dst_mac,
            'src_mac': src_mac,
            'eth_type': eth_type,
        }

        # Parse IP packet if present
        if eth_type == 0x0800:  # IPv4
            ip_info = self._parse_ipv4(data[14:])
            eth_info.update(ip_info)
        elif eth_type == 0x0806:  # ARP
            eth_info['protocol'] = 'ARP'
        elif eth_type == 0x86DD:  # IPv6
            eth_info['protocol'] = 'IPv6'

        return eth_info

    def _parse_ipv4(self, data: bytes) -> Dict:
        """Parse IPv4 packet"""
        if len(data) < 20:
            return {}

        # Parse IP header
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        ttl = data[8]
        protocol = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        ip_info = {
            'protocol': self._get_protocol_name(protocol),
            'protocol_num': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ttl': ttl,
        }

        # Parse transport layer
        if protocol == 6:  # TCP
            tcp_info = self._parse_tcp(data[ihl:])
            ip_info.update(tcp_info)
        elif protocol == 17:  # UDP
            udp_info = self._parse_udp(data[ihl:])
            ip_info.update(udp_info)
        elif protocol == 1:  # ICMP
            ip_info['protocol'] = 'ICMP'

        return ip_info

    def _parse_tcp(self, data: bytes) -> Dict:
        """Parse TCP segment"""
        if len(data) < 20:
            return {}

        src_port = struct.unpack('!H', data[0:2])[0]
        dst_port = struct.unpack('!H', data[2:4])[0]
        seq_num = struct.unpack('!I', data[4:8])[0]
        ack_num = struct.unpack('!I', data[8:12])[0]

        flags = data[13]
        flag_str = []
        if flags & 0x01:
            flag_str.append('FIN')
        if flags & 0x02:
            flag_str.append('SYN')
        if flags & 0x04:
            flag_str.append('RST')
        if flags & 0x08:
            flag_str.append('PSH')
        if flags & 0x10:
            flag_str.append('ACK')
        if flags & 0x20:
            flag_str.append('URG')

        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'tcp_seq': seq_num,
            'tcp_ack': ack_num,
            'tcp_flags': ','.join(flag_str) if flag_str else 'NONE',
        }

    def _parse_udp(self, data: bytes) -> Dict:
        """Parse UDP datagram"""
        if len(data) < 8:
            return {}

        src_port = struct.unpack('!H', data[0:2])[0]
        dst_port = struct.unpack('!H', data[2:4])[0]
        length = struct.unpack('!H', data[4:6])[0]

        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'udp_length': length,
        }

    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

    def _update_statistics(self, packet: Dict) -> None:
        """Update packet statistics"""
        protocol = packet.get('protocol', 'Unknown')
        self.statistics[f'protocol_{protocol}'] += 1

        if 'src_ip' in packet:
            self.statistics[f"src_ip_{packet['src_ip']}"] += 1
            self.statistics[f"dst_ip_{packet['dst_ip']}"] += 1

        if 'src_port' in packet:
            self.statistics[f"src_port_{packet['src_port']}"] += 1
            self.statistics[f"dst_port_{packet['dst_port']}"] += 1

            # Track conversations
            if 'src_ip' in packet:
                conv_key = f"{packet['src_ip']}:{packet.get('src_port')} -> {packet['dst_ip']}:{packet.get('dst_port')}"
                self.conversations[conv_key].append(packet)

    def detect_suspicious_activity(self) -> List[Dict]:
        """
        Detect suspicious network activity patterns.

        Returns:
            List of suspicious activity alerts
        """
        logger.info("Analyzing for suspicious activity...")

        alerts = []

        # Detect port scanning
        for key, count in self.statistics.items():
            if key.startswith('src_ip_'):
                ip = key.split('_', 2)[2]
                # Count unique destination ports from this IP
                dest_ports = set()
                for packet in self.packets:
                    if packet.get('src_ip') == ip and 'dst_port' in packet:
                        dest_ports.add(packet['dst_port'])

                if len(dest_ports) > 100:  # Port scan threshold
                    alerts.append({
                        'type': 'PORT_SCAN',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'unique_ports': len(dest_ports),
                        'description': f'Possible port scan detected from {ip} ({len(dest_ports)} ports contacted)'
                    })

        # Detect SYN flood
        syn_counts = defaultdict(int)
        for packet in self.packets:
            if packet.get('tcp_flags') == 'SYN':
                src_ip = packet.get('src_ip', 'unknown')
                syn_counts[src_ip] += 1

        for ip, count in syn_counts.items():
            if count > 1000:  # SYN flood threshold
                alerts.append({
                    'type': 'SYN_FLOOD',
                    'severity': 'CRITICAL',
                    'source_ip': ip,
                    'syn_count': count,
                    'description': f'Possible SYN flood attack from {ip} ({count} SYN packets)'
                })

        # Detect unusual ports
        suspicious_ports = [4444, 31337, 12345, 6667, 6666]  # Common backdoor ports
        for packet in self.packets:
            dst_port = packet.get('dst_port')
            src_port = packet.get('src_port')

            if dst_port in suspicious_ports or src_port in suspicious_ports:
                alerts.append({
                    'type': 'SUSPICIOUS_PORT',
                    'severity': 'MEDIUM',
                    'source_ip': packet.get('src_ip'),
                    'destination_ip': packet.get('dst_ip'),
                    'port': dst_port if dst_port in suspicious_ports else src_port,
                    'description': f'Communication on suspicious port detected'
                })

        # Detect DNS tunneling (excessive DNS queries)
        dns_counts = defaultdict(int)
        for packet in self.packets:
            if packet.get('dst_port') == 53:  # DNS
                src_ip = packet.get('src_ip', 'unknown')
                dns_counts[src_ip] += 1

        for ip, count in dns_counts.items():
            if count > 500:  # DNS tunneling threshold
                alerts.append({
                    'type': 'DNS_TUNNELING',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'dns_queries': count,
                    'description': f'Possible DNS tunneling from {ip} ({count} DNS queries)'
                })

        self.suspicious_activity = alerts
        logger.info(f"Found {len(alerts)} suspicious activities")
        return alerts

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get traffic statistics summary.

        Returns:
            Dictionary containing traffic statistics
        """
        stats = {
            'total_packets': len(self.packets),
            'protocols': {},
            'top_sources': {},
            'top_destinations': {},
            'top_ports': {},
        }

        # Protocol distribution
        for key, count in self.statistics.items():
            if key.startswith('protocol_'):
                protocol = key.split('_', 1)[1]
                stats['protocols'][protocol] = count

        # Top 10 source IPs
        src_ips = {k.split('_', 2)[2]: v for k, v in self.statistics.items() if k.startswith('src_ip_')}
        stats['top_sources'] = dict(sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10])

        # Top 10 destination IPs
        dst_ips = {k.split('_', 2)[2]: v for k, v in self.statistics.items() if k.startswith('dst_ip_')}
        stats['top_destinations'] = dict(sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10])

        # Top 10 ports
        ports = {k.split('_', 2)[2]: v for k, v in self.statistics.items() if k.startswith('dst_port_')}
        stats['top_ports'] = dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10])

        return stats

    def generate_report(self, output_path: str, format: str = 'json') -> None:
        """
        Generate network analysis report.

        Args:
            output_path: Path to save report
            format: Report format ('json' or 'html')
        """
        if format == 'json':
            report = {
                'summary': {
                    'total_packets': len(self.packets),
                    'analysis_date': datetime.now().isoformat(),
                },
                'statistics': self.get_statistics(),
                'suspicious_activity': self.suspicious_activity,
                'conversations': {
                    k: len(v) for k, v in self.conversations.items()
                },
            }

            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)

        elif format == 'html':
            self._generate_html_report(output_path)

        logger.info(f"Report saved to {output_path}")

    def _generate_html_report(self, output_path: str) -> None:
        """Generate HTML report"""
        stats = self.get_statistics()

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .alert {{ padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .alert-critical {{ background: #f8d7da; border-left: 5px solid #dc3545; }}
        .alert-high {{ background: #fff3cd; border-left: 5px solid #ffc107; }}
        .alert-medium {{ background: #d1ecf1; border-left: 5px solid #17a2b8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #007bff; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 5px; border-left: 4px solid #007bff; }}
        .stat-number {{ font-size: 32px; font-weight: bold; color: #007bff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Traffic Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <h2>📊 Summary Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats['total_packets']}</div>
                <div>Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(self.suspicious_activity)}</div>
                <div>Suspicious Activities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(self.conversations)}</div>
                <div>Conversations</div>
            </div>
        </div>

        <h2>⚠️ Suspicious Activity</h2>
"""

        if self.suspicious_activity:
            for alert in self.suspicious_activity:
                severity = alert['severity'].lower()
                html += f"""
        <div class="alert alert-{severity}">
            <strong>[{alert['severity']}] {alert['type']}</strong><br>
            {alert['description']}
        </div>
"""
        else:
            html += "<p>No suspicious activity detected.</p>"

        html += """
        <h2>📈 Protocol Distribution</h2>
        <table>
            <tr><th>Protocol</th><th>Packet Count</th></tr>
"""
        for protocol, count in stats['protocols'].items():
            html += f"            <tr><td>{protocol}</td><td>{count}</td></tr>\n"

        html += """
        </table>

        <h2>🌐 Top Source IPs</h2>
        <table>
            <tr><th>IP Address</th><th>Packet Count</th></tr>
"""
        for ip, count in stats['top_sources'].items():
            html += f"            <tr><td>{ip}</td><td>{count}</td></tr>\n"

        html += """
        </table>

        <h2>🎯 Top Destination Ports</h2>
        <table>
            <tr><th>Port</th><th>Packet Count</th></tr>
"""
        for port, count in stats['top_ports'].items():
            html += f"            <tr><td>{port}</td><td>{count}</td></tr>\n"

        html += """
        </table>
    </div>
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html)


def main():
    """Example usage of PacketAnalyzer"""
    import argparse

    parser = argparse.ArgumentParser(description='Network Packet Analyzer')
    parser.add_argument('--pcap', required=True, help='PCAP file to analyze')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--format', choices=['json', 'html'], default='html', help='Report format')

    args = parser.parse_args()

    analyzer = PacketAnalyzer()
    analyzer.parse_pcap_file(args.pcap)
    analyzer.detect_suspicious_activity()
    analyzer.generate_report(args.output, args.format)

    print(f"\n✓ Analysis complete: {len(analyzer.packets)} packets analyzed")
    print(f"✓ Report saved to: {args.output}")


if __name__ == '__main__':
    main()
