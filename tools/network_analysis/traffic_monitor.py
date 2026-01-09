"""
Traffic Monitor Tool
Real-time network traffic monitoring and anomaly detection.
"""

import socket
import struct
import time
import threading
import logging
from datetime import datetime
from typing import Dict, List, Callable
from collections import defaultdict, deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TrafficMonitor:
    """
    Real-time network traffic monitor with anomaly detection.
    Monitors live network traffic and identifies suspicious patterns.
    """

    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
        self.is_monitoring = False
        self.packet_queue = deque(maxlen=10000)
        self.statistics = defaultdict(int)
        self.rate_tracker = defaultdict(lambda: deque(maxlen=60))
        self.alerts = []
        self.callbacks = []

    def start_monitoring(self, duration: int = 0) -> None:
        """
        Start monitoring network traffic.

        Args:
            duration: Monitoring duration in seconds (0 = infinite)
        """
        logger.info(f"Starting traffic monitoring on {self.interface}")
        self.is_monitoring = True

        try:
            # Create raw socket (requires root/admin privileges)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.bind((self.interface, 0))

            start_time = time.time()

            while self.is_monitoring:
                if duration > 0 and (time.time() - start_time) > duration:
                    break

                try:
                    # Receive packet
                    raw_data, addr = sock.recvfrom(65535)
                    timestamp = datetime.now()

                    # Parse packet
                    packet = self._parse_packet(raw_data, timestamp)

                    if packet:
                        self.packet_queue.append(packet)
                        self._update_statistics(packet)
                        self._check_anomalies(packet)

                except Exception as e:
                    logger.error(f"Error receiving packet: {e}")

        except PermissionError:
            logger.error("Root/Administrator privileges required for packet capture")
            logger.info("Entering simulation mode...")
            self._simulate_monitoring(duration)

        except Exception as e:
            logger.error(f"Error starting monitor: {e}")

        finally:
            self.is_monitoring = False
            logger.info("Monitoring stopped")

    def _simulate_monitoring(self, duration: int) -> None:
        """
        Simulate network monitoring for testing without root privileges.
        """
        logger.info("Simulating network traffic...")

        import random

        protocols = ['TCP', 'UDP', 'ICMP']
        ips = [f'192.168.1.{i}' for i in range(1, 20)]

        start_time = time.time()

        while self.is_monitoring:
            if duration > 0 and (time.time() - start_time) > duration:
                break

            # Generate random packet
            packet = {
                'timestamp': datetime.now(),
                'protocol': random.choice(protocols),
                'src_ip': random.choice(ips),
                'dst_ip': random.choice(ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 3306, 8080]),
                'length': random.randint(64, 1500),
            }

            self.packet_queue.append(packet)
            self._update_statistics(packet)
            self._check_anomalies(packet)

            time.sleep(0.01)  # Simulate packet rate

    def stop_monitoring(self) -> None:
        """Stop network monitoring"""
        logger.info("Stopping traffic monitor...")
        self.is_monitoring = False

    def _parse_packet(self, raw_data: bytes, timestamp: datetime) -> Dict:
        """Parse raw packet data"""
        try:
            # Ethernet header
            eth_header = raw_data[:14]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            packet = {
                'timestamp': timestamp,
                'length': len(raw_data),
            }

            # IPv4
            if eth_protocol == 8:
                ip_header = raw_data[14:34]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])

                packet['src_ip'] = src_ip
                packet['dst_ip'] = dst_ip

                if protocol == 6:  # TCP
                    packet['protocol'] = 'TCP'
                    tcp_header = raw_data[34:54]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    packet['src_port'] = tcph[0]
                    packet['dst_port'] = tcph[1]

                elif protocol == 17:  # UDP
                    packet['protocol'] = 'UDP'
                    udp_header = raw_data[34:42]
                    udph = struct.unpack('!HHHH', udp_header)
                    packet['src_port'] = udph[0]
                    packet['dst_port'] = udph[1]

                elif protocol == 1:  # ICMP
                    packet['protocol'] = 'ICMP'

            return packet

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    def _update_statistics(self, packet: Dict) -> None:
        """Update traffic statistics"""
        current_time = int(time.time())

        # Protocol counts
        protocol = packet.get('protocol', 'Unknown')
        self.statistics[f'protocol_{protocol}'] += 1

        # Traffic rate tracking
        self.rate_tracker['packets_per_second'][current_time] += 1

        if 'src_ip' in packet:
            self.statistics[f"src_ip_{packet['src_ip']}"] += 1
            self.rate_tracker[f"rate_{packet['src_ip']}"][current_time] += 1

        if 'dst_port' in packet:
            self.statistics[f"dst_port_{packet['dst_port']}"] += 1

    def _check_anomalies(self, packet: Dict) -> None:
        """
        Check for network anomalies and suspicious patterns.
        """
        current_time = int(time.time())

        # Check for high packet rate from single source
        if 'src_ip' in packet:
            src_ip = packet['src_ip']
            rate_key = f"rate_{src_ip}"

            # Get packet rate for last 10 seconds
            recent_packets = sum(
                count for ts, count in self.rate_tracker[rate_key]
                if current_time - ts < 10
            )

            if recent_packets > 1000:  # High rate threshold
                alert = {
                    'type': 'HIGH_TRAFFIC_RATE',
                    'severity': 'WARNING',
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': src_ip,
                    'packet_rate': recent_packets,
                    'description': f'High packet rate from {src_ip}: {recent_packets} packets/10s'
                }
                self.alerts.append(alert)
                self._trigger_callbacks(alert)

        # Check for port scanning behavior
        if 'src_ip' in packet and 'dst_port' in packet:
            src_ip = packet['src_ip']

            # Count unique destination ports from this IP
            unique_ports = set()
            for pkt in list(self.packet_queue)[-1000:]:  # Check last 1000 packets
                if pkt.get('src_ip') == src_ip and 'dst_port' in pkt:
                    unique_ports.add(pkt['dst_port'])

            if len(unique_ports) > 50:  # Port scan threshold
                alert = {
                    'type': 'PORT_SCAN_DETECTED',
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': src_ip,
                    'unique_ports': len(unique_ports),
                    'description': f'Possible port scan from {src_ip}: {len(unique_ports)} unique ports'
                }
                self.alerts.append(alert)
                self._trigger_callbacks(alert)

        # Check for suspicious ports
        suspicious_ports = [4444, 31337, 12345, 6667, 1337, 8888, 9999]
        if 'dst_port' in packet and packet['dst_port'] in suspicious_ports:
            alert = {
                'type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM',
                'timestamp': datetime.now().isoformat(),
                'source_ip': packet.get('src_ip'),
                'destination_ip': packet.get('dst_ip'),
                'port': packet['dst_port'],
                'description': f"Traffic on suspicious port {packet['dst_port']}"
            }
            self.alerts.append(alert)
            self._trigger_callbacks(alert)

    def register_callback(self, callback: Callable) -> None:
        """
        Register a callback function to be called when alerts are generated.

        Args:
            callback: Function that takes an alert dictionary as parameter
        """
        self.callbacks.append(callback)

    def _trigger_callbacks(self, alert: Dict) -> None:
        """Trigger all registered callbacks with an alert"""
        for callback in self.callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in callback: {e}")

    def get_statistics(self) -> Dict:
        """Get current traffic statistics"""
        stats = {
            'total_packets': len(self.packet_queue),
            'total_alerts': len(self.alerts),
            'monitoring': self.is_monitoring,
            'protocols': {},
            'top_sources': {},
            'top_ports': {},
        }

        # Protocol breakdown
        for key, count in self.statistics.items():
            if key.startswith('protocol_'):
                protocol = key.split('_', 1)[1]
                stats['protocols'][protocol] = count

        # Top source IPs
        src_ips = {
            k.split('_', 2)[2]: v
            for k, v in self.statistics.items()
            if k.startswith('src_ip_')
        }
        stats['top_sources'] = dict(
            sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        )

        # Top ports
        ports = {
            k.split('_', 2)[2]: v
            for k, v in self.statistics.items()
            if k.startswith('dst_port_')
        }
        stats['top_ports'] = dict(
            sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
        )

        return stats

    def get_alerts(self, severity: str = None) -> List[Dict]:
        """
        Get generated alerts.

        Args:
            severity: Filter by severity level (WARNING, MEDIUM, HIGH, CRITICAL)

        Returns:
            List of alert dictionaries
        """
        if severity:
            return [a for a in self.alerts if a['severity'] == severity]
        return self.alerts

    def export_statistics(self, output_path: str) -> None:
        """
        Export monitoring statistics to file.

        Args:
            output_path: Path to save statistics
        """
        import json

        stats = self.get_statistics()
        stats['alerts'] = self.alerts

        with open(output_path, 'w') as f:
            json.dump(stats, f, indent=2, default=str)

        logger.info(f"Statistics exported to {output_path}")

    def display_live_stats(self, interval: int = 5) -> None:
        """
        Display live statistics in console.

        Args:
            interval: Update interval in seconds
        """
        import os
        import platform

        clear_cmd = 'cls' if platform.system() == 'Windows' else 'clear'

        while self.is_monitoring:
            os.system(clear_cmd)

            stats = self.get_statistics()

            print("=" * 70)
            print("LIVE NETWORK TRAFFIC MONITOR")
            print("=" * 70)
            print(f"Status: {'ACTIVE' if self.is_monitoring else 'STOPPED'}")
            print(f"Total Packets: {stats['total_packets']}")
            print(f"Total Alerts: {stats['total_alerts']}")
            print()

            print("Protocol Distribution:")
            print("-" * 70)
            for protocol, count in stats['protocols'].items():
                print(f"  {protocol}: {count}")
            print()

            print("Top Source IPs:")
            print("-" * 70)
            for ip, count in list(stats['top_sources'].items())[:5]:
                print(f"  {ip}: {count} packets")
            print()

            if self.alerts:
                print("Recent Alerts:")
                print("-" * 70)
                for alert in self.alerts[-5:]:
                    print(f"  [{alert['severity']}] {alert['type']}")
                    print(f"    {alert['description']}")
                print()

            print(f"Press Ctrl+C to stop monitoring")
            print("=" * 70)

            time.sleep(interval)


def alert_callback(alert: Dict) -> None:
    """Example callback function for alerts"""
    print(f"\n🚨 ALERT: [{alert['severity']}] {alert['type']}")
    print(f"   {alert['description']}")


def main():
    """Example usage of TrafficMonitor"""
    import argparse

    parser = argparse.ArgumentParser(description='Network Traffic Monitor')
    parser.add_argument('--interface', default='eth0', help='Network interface to monitor')
    parser.add_argument('--duration', type=int, default=0, help='Monitoring duration (0=infinite)')
    parser.add_argument('--output', help='Export statistics to file')
    parser.add_argument('--live', action='store_true', help='Display live statistics')

    args = parser.parse_args()

    monitor = TrafficMonitor(args.interface)
    monitor.register_callback(alert_callback)

    # Start monitoring in separate thread
    monitor_thread = threading.Thread(
        target=monitor.start_monitoring,
        args=(args.duration,)
    )
    monitor_thread.start()

    try:
        if args.live:
            monitor.display_live_stats()
        else:
            # Keep running until duration expires or Ctrl+C
            monitor_thread.join()

    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.stop_monitoring()
        monitor_thread.join()

    if args.output:
        monitor.export_statistics(args.output)

    print(f"\n✓ Monitoring complete")
    print(f"  Packets captured: {len(monitor.packet_queue)}")
    print(f"  Alerts generated: {len(monitor.alerts)}")


if __name__ == '__main__':
    main()
