"""
Attribution Engine
Correlates evidence from multiple sources to identify users responsible for cyber attacks.
This is the core engine for attacker identification.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Set, Tuple
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttributionEngine:
    """
    Advanced attribution engine that correlates evidence from multiple sources
    to identify and attribute cyber attacks to specific users/groups.
    """

    def __init__(self):
        self.evidence_sources = []
        self.indicators = defaultdict(list)
        self.suspects = []
        self.attribution_confidence = {}

    def add_evidence(self, source_type: str, evidence_data: Dict) -> None:
        """
        Add evidence from a source.

        Args:
            source_type: Type of evidence (network, file, social_media, etc.)
            evidence_data: Dictionary containing evidence
        """
        evidence = {
            'source_type': source_type,
            'timestamp': datetime.now().isoformat(),
            'data': evidence_data,
            'indicators_extracted': []
        }

        # Extract indicators based on source type
        if source_type == 'network':
            evidence['indicators_extracted'] = self._extract_network_indicators(evidence_data)
        elif source_type == 'file':
            evidence['indicators_extracted'] = self._extract_file_indicators(evidence_data)
        elif source_type == 'social_media':
            evidence['indicators_extracted'] = self._extract_social_indicators(evidence_data)
        elif source_type == 'email':
            evidence['indicators_extracted'] = self._extract_email_indicators(evidence_data)
        elif source_type == 'browser':
            evidence['indicators_extracted'] = self._extract_browser_indicators(evidence_data)

        self.evidence_sources.append(evidence)

        # Index indicators
        for indicator in evidence['indicators_extracted']:
            self.indicators[indicator['type']].append({
                'value': indicator['value'],
                'source': source_type,
                'confidence': indicator.get('confidence', 0.5)
            })

        logger.info(f"Added {source_type} evidence with {len(evidence['indicators_extracted'])} indicators")

    def _extract_network_indicators(self, data: Dict) -> List[Dict]:
        """Extract indicators from network traffic"""
        indicators = []

        if 'src_ip' in data:
            indicators.append({
                'type': 'ip_address',
                'value': data['src_ip'],
                'confidence': 0.8,
                'context': 'source_ip'
            })

        if 'dst_ip' in data:
            indicators.append({
                'type': 'ip_address',
                'value': data['dst_ip'],
                'confidence': 0.7,
                'context': 'destination_ip'
            })

        if 'user_agent' in data:
            indicators.append({
                'type': 'user_agent',
                'value': data['user_agent'],
                'confidence': 0.6
            })

        if 'hostname' in data:
            indicators.append({
                'type': 'hostname',
                'value': data['hostname'],
                'confidence': 0.7
            })

        return indicators

    def _extract_file_indicators(self, data: Dict) -> List[Dict]:
        """Extract indicators from file metadata"""
        indicators = []

        if 'author' in data:
            indicators.append({
                'type': 'author_name',
                'value': data['author'],
                'confidence': 0.9
            })

        if 'created_by' in data:
            indicators.append({
                'type': 'username',
                'value': data['created_by'],
                'confidence': 0.8
            })

        if 'file_hash' in data:
            indicators.append({
                'type': 'file_hash',
                'value': data['file_hash'],
                'confidence': 1.0
            })

        if 'compilation_timestamp' in data:
            indicators.append({
                'type': 'timestamp',
                'value': data['compilation_timestamp'],
                'confidence': 0.6
            })

        return indicators

    def _extract_social_indicators(self, data: Dict) -> List[Dict]:
        """Extract indicators from social media"""
        indicators = []

        if 'username' in data:
            indicators.append({
                'type': 'social_username',
                'value': data['username'],
                'confidence': 0.9
            })

        if 'email' in data:
            indicators.append({
                'type': 'email_address',
                'value': data['email'],
                'confidence': 0.95
            })

        if 'phone' in data:
            indicators.append({
                'type': 'phone_number',
                'value': data['phone'],
                'confidence': 0.95
            })

        if 'location' in data:
            indicators.append({
                'type': 'location',
                'value': data['location'],
                'confidence': 0.7
            })

        if 'real_name' in data:
            indicators.append({
                'type': 'real_name',
                'value': data['real_name'],
                'confidence': 0.8
            })

        return indicators

    def _extract_email_indicators(self, data: Dict) -> List[Dict]:
        """Extract indicators from email"""
        indicators = []

        if 'from_address' in data:
            indicators.append({
                'type': 'email_address',
                'value': data['from_address'],
                'confidence': 0.9
            })

        if 'sender_ip' in data:
            indicators.append({
                'type': 'ip_address',
                'value': data['sender_ip'],
                'confidence': 0.8
            })

        if 'x_mailer' in data:
            indicators.append({
                'type': 'email_client',
                'value': data['x_mailer'],
                'confidence': 0.6
            })

        return indicators

    def _extract_browser_indicators(self, data: Dict) -> List[Dict]:
        """Extract indicators from browser artifacts"""
        indicators = []

        if 'browsing_history' in data:
            for url in data['browsing_history'][:20]:  # Top 20
                if 'login' in url or 'account' in url:
                    indicators.append({
                        'type': 'visited_url',
                        'value': url,
                        'confidence': 0.5
                    })

        if 'cookies' in data:
            for cookie in data['cookies']:
                if 'user' in cookie.get('name', '').lower():
                    indicators.append({
                        'type': 'cookie_value',
                        'value': cookie.get('value'),
                        'confidence': 0.4
                    })

        return indicators

    def correlate_indicators(self) -> List[Dict]:
        """
        Correlate indicators across evidence sources to identify suspects.

        Returns:
            List of suspect profiles with attribution confidence
        """
        logger.info("Correlating indicators across evidence sources...")

        # Build suspect profiles based on shared indicators
        suspect_clusters = defaultdict(lambda: {
            'indicators': defaultdict(set),
            'evidence_sources': set(),
            'confidence_scores': []
        })

        # Find indicator overlaps
        for indicator_type, indicator_list in self.indicators.items():
            # Group by indicator value
            value_groups = defaultdict(list)
            for indicator in indicator_list:
                value_groups[indicator['value']].append(indicator)

            # If same indicator appears in multiple sources, it's significant
            for value, occurrences in value_groups.items():
                if len(occurrences) >= 2:  # Appears in 2+ sources
                    # Create or update suspect cluster
                    cluster_key = hashlib.md5(value.encode()).hexdigest()[:8]

                    for occurrence in occurrences:
                        suspect_clusters[cluster_key]['indicators'][indicator_type].add(value)
                        suspect_clusters[cluster_key]['evidence_sources'].add(occurrence['source'])
                        suspect_clusters[cluster_key]['confidence_scores'].append(occurrence['confidence'])

        # Convert clusters to suspect profiles
        suspects = []
        for cluster_id, cluster_data in suspect_clusters.items():
            # Calculate overall confidence
            confidence_scores = cluster_data['confidence_scores']
            avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0

            # Boost confidence based on number of different evidence sources
            source_bonus = len(cluster_data['evidence_sources']) * 0.1
            final_confidence = min(avg_confidence + source_bonus, 1.0)

            suspect = {
                'suspect_id': f'SUSPECT_{cluster_id}',
                'indicators': {k: list(v) for k, v in cluster_data['indicators'].items()},
                'evidence_sources': list(cluster_data['evidence_sources']),
                'num_indicators': sum(len(v) for v in cluster_data['indicators'].values()),
                'attribution_confidence': round(final_confidence, 2),
                'risk_level': self._assess_risk_level(final_confidence),
            }

            suspects.append(suspect)

        # Sort by confidence
        suspects.sort(key=lambda x: x['attribution_confidence'], reverse=True)

        self.suspects = suspects
        logger.info(f"Identified {len(suspects)} potential suspects")

        return suspects

    def _assess_risk_level(self, confidence: float) -> str:
        """Assess risk level based on attribution confidence"""
        if confidence >= 0.8:
            return "CRITICAL"
        elif confidence >= 0.6:
            return "HIGH"
        elif confidence >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def build_attack_timeline(self) -> List[Dict]:
        """
        Build timeline of attack events across all evidence sources.

        Returns:
            Chronological list of events
        """
        timeline = []

        for evidence in self.evidence_sources:
            event = {
                'timestamp': evidence['timestamp'],
                'source_type': evidence['source_type'],
                'indicators_found': len(evidence['indicators_extracted']),
                'summary': self._summarize_evidence(evidence)
            }
            timeline.append(event)

        # Sort chronologically
        timeline.sort(key=lambda x: x['timestamp'])

        return timeline

    def _summarize_evidence(self, evidence: Dict) -> str:
        """Create summary of evidence"""
        source_type = evidence['source_type']
        indicator_count = len(evidence['indicators_extracted'])

        summaries = {
            'network': f"Network activity detected with {indicator_count} indicators",
            'file': f"File analysis revealed {indicator_count} indicators",
            'social_media': f"Social media evidence with {indicator_count} identifiers",
            'email': f"Email evidence with {indicator_count} indicators",
            'browser': f"Browser artifacts with {indicator_count} indicators",
        }

        return summaries.get(source_type, f"{source_type} evidence with {indicator_count} indicators")

    def identify_attack_patterns(self) -> Dict:
        """
        Identify attack patterns and TTPs (Tactics, Techniques, Procedures).

        Returns:
            Dictionary with identified patterns
        """
        patterns = {
            'attack_vectors': [],
            'tools_used': [],
            'target_systems': [],
            'time_patterns': [],
            'sophistication_level': 'UNKNOWN'
        }

        # Analyze evidence for patterns
        tool_indicators = []
        timing_data = []

        for evidence in self.evidence_sources:
            data = evidence['data']

            # Identify tools
            if 'tool_name' in data:
                tool_indicators.append(data['tool_name'])

            if 'malware_family' in data:
                tool_indicators.append(data['malware_family'])

            # Timing patterns
            if 'timestamp' in data:
                timing_data.append(data['timestamp'])

        patterns['tools_used'] = list(set(tool_indicators))

        # Assess sophistication
        if len(self.evidence_sources) > 10 and len(self.suspects) <= 2:
            patterns['sophistication_level'] = 'HIGH'
        elif len(self.evidence_sources) > 5:
            patterns['sophistication_level'] = 'MEDIUM'
        else:
            patterns['sophistication_level'] = 'LOW'

        return patterns

    def generate_attribution_report(self, output_path: str) -> None:
        """
        Generate comprehensive attribution report.

        Args:
            output_path: Path to save report
        """
        with open(output_path, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("CYBER ATTACK ATTRIBUTION REPORT\n")
            f.write("=" * 100 + "\n\n")

            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Evidence Sources Analyzed: {len(self.evidence_sources)}\n")
            f.write(f"Indicators Extracted: {sum(len(v) for v in self.indicators.values())}\n")
            f.write(f"Suspects Identified: {len(self.suspects)}\n\n")

            # Attack patterns
            patterns = self.identify_attack_patterns()
            f.write("=" * 100 + "\n")
            f.write("ATTACK ANALYSIS\n")
            f.write("=" * 100 + "\n\n")
            f.write(f"Sophistication Level: {patterns['sophistication_level']}\n")
            if patterns['tools_used']:
                f.write(f"Tools/Malware Identified: {', '.join(patterns['tools_used'])}\n")
            f.write("\n")

            # Suspects
            f.write("=" * 100 + "\n")
            f.write("IDENTIFIED SUSPECTS\n")
            f.write("=" * 100 + "\n\n")

            for i, suspect in enumerate(self.suspects, 1):
                f.write(f"SUSPECT #{i}: {suspect['suspect_id']}\n")
                f.write("-" * 100 + "\n")
                f.write(f"Attribution Confidence: {suspect['attribution_confidence']*100:.0f}%\n")
                f.write(f"Risk Level: {suspect['risk_level']}\n")
                f.write(f"Evidence Sources: {', '.join(suspect['evidence_sources'])}\n")
                f.write(f"Total Indicators: {suspect['num_indicators']}\n\n")

                f.write("Indicators Found:\n")
                for indicator_type, values in suspect['indicators'].items():
                    f.write(f"  {indicator_type.upper()}: {', '.join(values)}\n")

                f.write("\n")

                # Provide investigative recommendations
                f.write("INVESTIGATIVE RECOMMENDATIONS:\n")
                if 'email_address' in suspect['indicators']:
                    f.write("  → Investigate email addresses for account ownership\n")
                if 'ip_address' in suspect['indicators']:
                    f.write("  → Trace IP addresses to ISP and obtain subscriber information\n")
                if 'social_username' in suspect['indicators']:
                    f.write("  → Investigate social media accounts for additional intelligence\n")
                if 'phone_number' in suspect['indicators']:
                    f.write("  → Trace phone numbers to subscriber information\n")

                f.write("\n" + "=" * 100 + "\n\n")

            # Timeline
            timeline = self.build_attack_timeline()
            f.write("ATTACK TIMELINE\n")
            f.write("=" * 100 + "\n\n")
            for event in timeline:
                f.write(f"{event['timestamp']} - {event['summary']}\n")

            f.write("\n" + "=" * 100 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 100 + "\n")

        logger.info(f"Attribution report saved to {output_path}")

    def export_for_law_enforcement(self, output_path: str) -> None:
        """
        Export evidence package formatted for law enforcement.

        Args:
            output_path: Path to save law enforcement package
        """
        package = {
            'report_metadata': {
                'generated': datetime.now().isoformat(),
                'case_reference': f"CASE_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'analyst': 'CyberForensics Toolkit',
            },
            'executive_summary': {
                'total_suspects': len(self.suspects),
                'highest_confidence': max([s['attribution_confidence'] for s in self.suspects]) if self.suspects else 0,
                'evidence_sources': len(self.evidence_sources),
            },
            'suspects': self.suspects,
            'all_indicators': {k: [{'value': i['value'], 'source': i['source']}
                                  for i in v] for k, v in self.indicators.items()},
            'timeline': self.build_attack_timeline(),
            'attack_patterns': self.identify_attack_patterns(),
        }

        with open(output_path, 'w') as f:
            json.dump(package, f, indent=2, default=str)

        logger.info(f"Law enforcement package exported to {output_path}")


def main():
    """Example usage of AttributionEngine"""
    import argparse

    parser = argparse.ArgumentParser(description='User Attribution Engine')
    parser.add_argument('--evidence-dir', help='Directory containing evidence files')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--le-export', help='Export for law enforcement')

    args = parser.parse_args()

    engine = AttributionEngine()

    # In real usage, evidence would be loaded from various sources
    # For demonstration:
    print("\n🔍 Cyber Attack Attribution Engine")
    print("=" * 60)

    # Example evidence addition (in real use, this comes from other tools)
    example_evidence = [
        ('network', {'src_ip': '192.168.1.100', 'dst_ip': '10.0.0.5', 'user_agent': 'Mozilla/5.0'}),
        ('file', {'author': 'JohnDoe', 'file_hash': 'abc123def456'}),
        ('social_media', {'username': 'john_doe_hacker', 'email': 'john@example.com'}),
    ]

    for source_type, data in example_evidence:
        engine.add_evidence(source_type, data)

    # Correlate and identify suspects
    suspects = engine.correlate_indicators()

    # Generate reports
    engine.generate_attribution_report(args.output)

    if args.le_export:
        engine.export_for_law_enforcement(args.le_export)

    print(f"\n✓ Attribution analysis complete")
    print(f"  Suspects identified: {len(suspects)}")
    print(f"  Report saved to: {args.output}")


if __name__ == '__main__':
    main()
