#!/usr/bin/env python3
"""
CyberForensics Toolkit - Main CLI Interface
Comprehensive digital forensics and cybersecurity investigation suite.
"""

import sys
import os
import argparse
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.file_forensics.file_recovery import FileRecoveryTool
from tools.file_forensics.metadata_analyzer import MetadataAnalyzer
from tools.network_analysis.packet_analyzer import PacketAnalyzer
from tools.network_analysis.traffic_monitor import TrafficMonitor
from tools.malware_analysis.static_analyzer import StaticMalwareAnalyzer
from tools.malware_analysis.signature_detector import SignatureDetector
from tools.password_recovery.hash_cracker import HashCracker
from tools.password_recovery.password_analyzer import PasswordAnalyzer
from tools.social_media_osint.profile_analyzer import ProfileAnalyzer
from tools.social_media_osint.activity_tracker import ActivityTracker
from tools.user_attribution.attribution_engine import AttributionEngine

import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print CLI banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗                                ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗                               ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝                               ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗                               ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║                               ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝                               ║
║                                                                           ║
║   ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗║
║   ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝║
║   █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗║
║   ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║║
║   ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝║
║                                                                           ║
║              Advanced Digital Forensics & Investigation Suite            ║
║                          Version 1.0.0                                    ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def file_forensics_command(args):
    """Handle file forensics commands"""
    if args.action == 'recover':
        tool = FileRecoveryTool()
        tool.scan_disk_image(args.image, args.output)
        if args.report:
            tool.generate_recovery_report(args.report)
        print(f"\n✓ File recovery complete: {len(tool.recovered_files)} files recovered")

    elif args.action == 'metadata':
        analyzer = MetadataAnalyzer()
        if args.file:
            analyzer.analyze_file(args.file)
        elif args.directory:
            analyzer.analyze_directory(args.directory, args.recursive)
        analyzer.generate_report(args.output, args.format)
        if args.timeline:
            analyzer.timeline_analysis(args.timeline)
        print(f"\n✓ Metadata analysis complete: {len(analyzer.analyzed_files)} files analyzed")


def network_analysis_command(args):
    """Handle network analysis commands"""
    if args.action == 'analyze-pcap':
        analyzer = PacketAnalyzer()
        analyzer.parse_pcap_file(args.pcap)
        analyzer.detect_suspicious_activity()
        analyzer.generate_report(args.output, args.format)
        print(f"\n✓ Network analysis complete: {len(analyzer.packets)} packets analyzed")

    elif args.action == 'monitor':
        monitor = TrafficMonitor(args.interface)
        # Start monitoring
        import threading
        monitor_thread = threading.Thread(target=monitor.start_monitoring, args=(args.duration,))
        monitor_thread.start()
        try:
            if args.live:
                monitor.display_live_stats()
            else:
                monitor_thread.join()
        except KeyboardInterrupt:
            monitor.stop_monitoring()
        if args.output:
            monitor.export_statistics(args.output)
        print(f"\n✓ Monitoring complete: {len(monitor.alerts)} alerts generated")


def malware_analysis_command(args):
    """Handle malware analysis commands"""
    if args.action == 'static-analysis':
        analyzer = StaticMalwareAnalyzer()
        if args.file:
            analyzer.analyze_file(args.file)
        elif args.directory:
            analyzer.scan_directory(args.directory, args.recursive)
        analyzer.generate_report(args.output, args.format)
        print(f"\n✓ Malware analysis complete: {len(analyzer.analysis_results)} files analyzed")

    elif args.action == 'signature-scan':
        detector = SignatureDetector()
        if args.rules:
            detector.load_rules_from_file(args.rules)
        if args.file:
            result = detector.scan_file(args.file)
            if result['is_malicious']:
                print(f"\n⚠️  THREAT DETECTED: {result['threat_level']}")
            else:
                print(f"\n✓ File is clean")
        elif args.directory:
            detector.scan_directory(args.directory, args.recursive)

        detector.generate_report(args.output, args.format)
        stats = detector.get_statistics()
        print(f"\n✓ Scan complete: {stats['infected_files']} threats found")


def password_recovery_command(args):
    """Handle password recovery commands"""
    if args.action == 'crack-hash':
        cracker = HashCracker(max_workers=args.workers)

        password = None
        if args.smart:
            context = {'username': args.username} if args.username else {}
            password = cracker.crack_hash_smart(args.hash, args.algorithm, context)
        elif args.wordlist:
            password = cracker.crack_hash_dictionary(args.hash, args.algorithm, args.wordlist)
        elif args.bruteforce:
            password = cracker.crack_hash_bruteforce(args.hash, args.algorithm, max_length=args.max_length)

        if password:
            print(f"\n✓ PASSWORD CRACKED: {password}")
            analysis = cracker.analyze_password_strength(password)
            print(f"  Strength: {analysis['strength']}")
            print(f"  Entropy: {analysis['entropy_bits']} bits")
        else:
            print(f"\n✗ Failed to crack hash")

    elif args.action == 'analyze-dump':
        analyzer = PasswordAnalyzer()
        analyzer.load_password_dump(args.dump, args.format_type)
        analyzer.analyze_patterns()
        analyzer.generate_report(args.output)
        if args.wordlist:
            analyzer.generate_wordlist(args.wordlist)
        print(f"\n✓ Password dump analysis complete")


def osint_command(args):
    """Handle OSINT commands"""
    if args.action == 'profile-analysis':
        analyzer = ProfileAnalyzer()
        results = analyzer.analyze_username(args.username, args.platforms)

        if results['potential_profiles']:
            profile = analyzer.build_comprehensive_profile(results['potential_profiles'])

        analyzer.generate_report(args.output, args.format)
        print(f"\n✓ OSINT analysis complete")
        print(f"  Platforms found: {len(results['platforms_found'])}")
        print(f"  Report saved to: {args.output}")

    elif args.action == 'activity-tracking':
        tracker = ActivityTracker()
        tracker.load_activities(args.activities)
        tracker.analyze_activity_patterns()
        tracker.generate_report(args.output)
        print(f"\n✓ Activity tracking complete")


def attribution_command(args):
    """Handle user attribution commands"""
    engine = AttributionEngine()

    # Load evidence from multiple sources
    if args.network_evidence:
        import json
        with open(args.network_evidence, 'r') as f:
            data = json.load(f)
            engine.add_evidence('network', data)

    if args.file_evidence:
        import json
        with open(args.file_evidence, 'r') as f:
            data = json.load(f)
            engine.add_evidence('file', data)

    if args.social_evidence:
        import json
        with open(args.social_evidence, 'r') as f:
            data = json.load(f)
            engine.add_evidence('social_media', data)

    # Correlate and identify suspects
    suspects = engine.correlate_indicators()

    # Generate reports
    engine.generate_attribution_report(args.output)

    if args.le_export:
        engine.export_for_law_enforcement(args.le_export)

    print(f"\n✓ Attribution analysis complete")
    print(f"  Suspects identified: {len(suspects)}")
    if suspects:
        top_suspect = suspects[0]
        print(f"  Top suspect confidence: {top_suspect['attribution_confidence']*100:.0f}%")
    print(f"  Report saved to: {args.output}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='CyberForensics Toolkit - Advanced Digital Forensics Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='module', help='Forensics module to use')

    # File Forensics
    file_parser = subparsers.add_parser('file-forensics', help='File recovery and metadata analysis')
    file_parser.add_argument('action', choices=['recover', 'metadata'], help='Action to perform')
    file_parser.add_argument('--image', help='Disk image path for recovery')
    file_parser.add_argument('--file', help='Single file to analyze')
    file_parser.add_argument('--directory', help='Directory to analyze')
    file_parser.add_argument('--recursive', action='store_true', help='Recursive analysis')
    file_parser.add_argument('--output', required=True, help='Output path')
    file_parser.add_argument('--report', help='Recovery report path')
    file_parser.add_argument('--timeline', help='Generate timeline')
    file_parser.add_argument('--format', choices=['json', 'text'], default='json', help='Report format')

    # Network Analysis
    network_parser = subparsers.add_parser('network', help='Network traffic analysis')
    network_parser.add_argument('action', choices=['analyze-pcap', 'monitor'], help='Action to perform')
    network_parser.add_argument('--pcap', help='PCAP file to analyze')
    network_parser.add_argument('--interface', default='eth0', help='Network interface')
    network_parser.add_argument('--duration', type=int, default=0, help='Monitoring duration')
    network_parser.add_argument('--live', action='store_true', help='Live stats display')
    network_parser.add_argument('--output', required=True, help='Output path')
    network_parser.add_argument('--format', choices=['json', 'html'], default='html', help='Report format')

    # Malware Analysis
    malware_parser = subparsers.add_parser('malware', help='Malware analysis')
    malware_parser.add_argument('action', choices=['static-analysis', 'signature-scan'], help='Action')
    malware_parser.add_argument('--file', help='File to analyze')
    malware_parser.add_argument('--directory', help='Directory to scan')
    malware_parser.add_argument('--recursive', action='store_true', help='Recursive scan')
    malware_parser.add_argument('--rules', help='Custom YARA-like rules file')
    malware_parser.add_argument('--output', required=True, help='Output report path')
    malware_parser.add_argument('--format', choices=['text', 'json'], default='text', help='Format')

    # Password Recovery
    password_parser = subparsers.add_parser('password', help='Password recovery')
    password_parser.add_argument('action', choices=['crack-hash', 'analyze-dump'], help='Action')
    password_parser.add_argument('--hash', help='Hash to crack')
    password_parser.add_argument('--algorithm', help='Hash algorithm')
    password_parser.add_argument('--wordlist', help='Wordlist file')
    password_parser.add_argument('--bruteforce', action='store_true', help='Brute force')
    password_parser.add_argument('--smart', action='store_true', help='AI-assisted attack')
    password_parser.add_argument('--username', help='Username for context')
    password_parser.add_argument('--max-length', type=int, default=6, help='Max length')
    password_parser.add_argument('--workers', type=int, default=4, help='Worker processes')
    password_parser.add_argument('--dump', help='Password dump file')
    password_parser.add_argument('--format-type', default='auto', help='Dump format')
    password_parser.add_argument('--output', required=True, help='Output report')

    # OSINT
    osint_parser = subparsers.add_parser('osint', help='Social media OSINT')
    osint_parser.add_argument('action', choices=['profile-analysis', 'activity-tracking'], help='Action')
    osint_parser.add_argument('--username', help='Username to investigate')
    osint_parser.add_argument('--platforms', nargs='+', help='Platforms to check')
    osint_parser.add_argument('--activities', help='Activities JSON file')
    osint_parser.add_argument('--output', required=True, help='Output report')
    osint_parser.add_argument('--format', choices=['json', 'html'], default='html', help='Format')

    # Attribution
    attrib_parser = subparsers.add_parser('attribution', help='User attribution analysis')
    attrib_parser.add_argument('--network-evidence', help='Network evidence file')
    attrib_parser.add_argument('--file-evidence', help='File evidence file')
    attrib_parser.add_argument('--social-evidence', help='Social media evidence file')
    attrib_parser.add_argument('--output', required=True, help='Attribution report output')
    attrib_parser.add_argument('--le-export', help='Law enforcement export file')

    args = parser.parse_args()

    if not args.module:
        print_banner()
        parser.print_help()
        return

    print_banner()
    print(f"\n🔧 Module: {args.module.upper()}")
    print("=" * 80 + "\n")

    # Route to appropriate command handler
    try:
        if args.module == 'file-forensics':
            file_forensics_command(args)
        elif args.module == 'network':
            network_analysis_command(args)
        elif args.module == 'malware':
            malware_analysis_command(args)
        elif args.module == 'password':
            password_recovery_command(args)
        elif args.module == 'osint':
            osint_command(args)
        elif args.module == 'attribution':
            attribution_command(args)

    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
