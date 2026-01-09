"""
Social Media Profile Analyzer
Advanced OSINT tool for gathering and analyzing social media profiles.
Identifies users, tracks activities, and builds comprehensive user profiles.
"""

import re
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import defaultdict
import logging
from pathlib import Path
from urllib.parse import urlparse, urljoin
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProfileAnalyzer:
    """
    Comprehensive social media OSINT tool.
    Analyzes user profiles across multiple platforms for forensic investigation.
    """

    SUPPORTED_PLATFORMS = [
        'twitter', 'facebook', 'instagram', 'linkedin', 'reddit',
        'github', 'tiktok', 'telegram', 'discord', 'youtube'
    ]

    def __init__(self):
        self.profiles = []
        self.consolidated_profile = {}
        self.connections = []
        self.timeline_events = []

    def analyze_username(self, username: str, platforms: List[str] = None) -> Dict:
        """
        Analyze a username across multiple platforms.

        Args:
            username: Username to investigate
            platforms: List of platforms to check (default: all)

        Returns:
            Dictionary with findings across platforms
        """
        if platforms is None:
            platforms = self.SUPPORTED_PLATFORMS

        logger.info(f"Analyzing username: {username} across {len(platforms)} platforms")

        results = {
            'username': username,
            'search_timestamp': datetime.now().isoformat(),
            'platforms_found': [],
            'potential_profiles': [],
            'cross_platform_indicators': {},
        }

        for platform in platforms:
            logger.info(f"Checking {platform}...")
            profile_data = self._check_platform(username, platform)

            if profile_data['likely_exists']:
                results['platforms_found'].append(platform)
                results['potential_profiles'].append(profile_data)

        # Analyze cross-platform patterns
        results['cross_platform_indicators'] = self._analyze_cross_platform_patterns(
            results['potential_profiles']
        )

        return results

    def _check_platform(self, username: str, platform: str) -> Dict:
        """
        Check if username exists on a platform.
        Returns profile information and existence likelihood.
        """
        # Generate platform-specific URLs
        profile_urls = {
            'twitter': f'https://twitter.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'github': f'https://github.com/{username}',
            'tiktok': f'https://tiktok.com/@{username}',
            'telegram': f'https://t.me/{username}',
            'youtube': f'https://youtube.com/@{username}',
        }

        profile_data = {
            'platform': platform,
            'username': username,
            'url': profile_urls.get(platform, ''),
            'likely_exists': False,  # In real implementation, would check HTTP status
            'profile_info': {},
            'collection_method': 'OSINT',
        }

        # Note: In real implementation, this would make HTTP requests
        # For now, we'll provide structure for data collection

        return profile_data

    def _analyze_cross_platform_patterns(self, profiles: List[Dict]) -> Dict:
        """
        Analyze patterns across multiple platform profiles.
        Helps identify if profiles belong to same person.
        """
        indicators = {
            'username_variations': [],
            'common_themes': [],
            'temporal_patterns': [],
            'confidence_score': 0,
        }

        # Analyze username patterns
        usernames = [p['username'] for p in profiles]
        indicators['username_variations'] = self._find_username_variations(usernames)

        # Calculate confidence that profiles belong to same person
        if len(profiles) > 1:
            # Multiple platforms with same username increases confidence
            indicators['confidence_score'] = min(len(profiles) * 20, 90)

        return indicators

    def _find_username_variations(self, usernames: List[str]) -> List[str]:
        """Find common patterns in username variations"""
        variations = set()

        for username in usernames:
            # Remove numbers
            base = re.sub(r'\d+', '', username)
            if base != username:
                variations.add(f"Base form: {base}")

            # Remove underscores/dots
            clean = username.replace('_', '').replace('.', '')
            if clean != username:
                variations.add(f"Clean form: {clean}")

        return list(variations)

    def build_comprehensive_profile(self, profiles_data: List[Dict]) -> Dict:
        """
        Build comprehensive user profile from multiple sources.

        Args:
            profiles_data: List of profile dictionaries from different platforms

        Returns:
            Consolidated profile with all information
        """
        logger.info("Building comprehensive user profile...")

        consolidated = {
            'primary_identifiers': {
                'usernames': set(),
                'email_addresses': set(),
                'phone_numbers': set(),
                'real_names': set(),
            },
            'demographics': {
                'locations': set(),
                'languages': set(),
                'timezones': set(),
            },
            'online_presence': {
                'platforms': {},
                'total_platforms': 0,
                'account_creation_dates': {},
            },
            'behavioral_analysis': {
                'activity_patterns': {},
                'interests': set(),
                'connections_count': 0,
            },
            'digital_footprint': {
                'posted_content_count': 0,
                'media_shared': [],
                'external_links': set(),
            },
            'risk_indicators': [],
            'investigation_notes': [],
        }

        for profile in profiles_data:
            platform = profile.get('platform', 'unknown')
            info = profile.get('profile_info', {})

            # Collect identifiers
            if 'username' in profile:
                consolidated['primary_identifiers']['usernames'].add(profile['username'])

            if 'email' in info:
                consolidated['primary_identifiers']['email_addresses'].add(info['email'])

            if 'name' in info:
                consolidated['primary_identifiers']['real_names'].add(info['name'])

            # Collect demographics
            if 'location' in info:
                consolidated['demographics']['locations'].add(info['location'])

            if 'language' in info:
                consolidated['demographics']['languages'].add(info['language'])

            # Online presence
            consolidated['online_presence']['platforms'][platform] = profile.get('url', '')
            consolidated['online_presence']['total_platforms'] += 1

            if 'created_date' in info:
                consolidated['online_presence']['account_creation_dates'][platform] = info['created_date']

            # Behavioral data
            if 'interests' in info:
                consolidated['behavioral_analysis']['interests'].update(info['interests'])

            if 'followers' in info or 'connections' in info:
                count = info.get('followers', info.get('connections', 0))
                consolidated['behavioral_analysis']['connections_count'] += count

        # Convert sets to lists for JSON serialization
        consolidated['primary_identifiers'] = {
            k: list(v) for k, v in consolidated['primary_identifiers'].items()
        }
        consolidated['demographics'] = {
            k: list(v) for k, v in consolidated['demographics'].items()
        }
        consolidated['behavioral_analysis']['interests'] = list(
            consolidated['behavioral_analysis']['interests']
        )
        consolidated['digital_footprint']['external_links'] = list(
            consolidated['digital_footprint']['external_links']
        )

        self.consolidated_profile = consolidated
        return consolidated

    def extract_timeline(self, profile_data: Dict) -> List[Dict]:
        """
        Extract activity timeline from profile data.

        Args:
            profile_data: Profile information with activity data

        Returns:
            List of timeline events
        """
        timeline = []

        # Extract various events
        posts = profile_data.get('posts', [])
        for post in posts:
            timeline.append({
                'timestamp': post.get('date'),
                'type': 'POST',
                'platform': profile_data.get('platform'),
                'content': post.get('text', '')[:100],  # First 100 chars
                'engagement': post.get('likes', 0) + post.get('shares', 0),
            })

        # Extract account events
        if 'created_date' in profile_data:
            timeline.append({
                'timestamp': profile_data['created_date'],
                'type': 'ACCOUNT_CREATED',
                'platform': profile_data.get('platform'),
                'content': 'Account created',
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        self.timeline_events.extend(timeline)
        return timeline

    def analyze_connections(self, profile_data: Dict) -> Dict:
        """
        Analyze social connections and network.

        Args:
            profile_data: Profile with connections data

        Returns:
            Connection analysis
        """
        analysis = {
            'total_connections': 0,
            'connection_types': {},
            'influential_connections': [],
            'suspicious_connections': [],
            'connection_growth_pattern': 'normal',
        }

        followers = profile_data.get('followers', [])
        following = profile_data.get('following', [])

        analysis['total_connections'] = len(followers) + len(following)
        analysis['connection_types'] = {
            'followers': len(followers),
            'following': len(following),
            'ratio': len(followers) / len(following) if following else 0,
        }

        # Identify suspicious patterns
        if len(followers) > 10000 and profile_data.get('posts_count', 0) < 10:
            analysis['suspicious_connections'].append('High followers with low activity')

        if len(following) > len(followers) * 10:
            analysis['suspicious_connections'].append('Follows significantly more than followers')

        return analysis

    def identify_personas(self, profiles: List[Dict]) -> List[Dict]:
        """
        Identify different personas/identities used by the same individual.

        Args:
            profiles: List of profiles to analyze

        Returns:
            List of identified personas with characteristics
        """
        personas = []

        # Group profiles by similarity
        for profile in profiles:
            persona = {
                'username': profile.get('username'),
                'platform': profile.get('platform'),
                'characteristics': [],
                'purpose_assessment': '',
            }

            # Analyze persona characteristics
            info = profile.get('profile_info', {})

            if info.get('posts_count', 0) > 100:
                persona['characteristics'].append('Active poster')

            if info.get('followers', 0) > 1000:
                persona['characteristics'].append('Influential')

            # Assess likely purpose
            interests = info.get('interests', [])
            if any(word in str(interests).lower() for word in ['hack', 'security', 'crypto']):
                persona['purpose_assessment'] = 'Technical/Security Interest'
            elif any(word in str(interests).lower() for word in ['business', 'marketing']):
                persona['purpose_assessment'] = 'Professional'
            else:
                persona['purpose_assessment'] = 'Personal/Social'

            personas.append(persona)

        return personas

    def detect_fake_accounts(self, profile_data: Dict) -> Dict:
        """
        Detect indicators of fake or bot accounts.

        Args:
            profile_data: Profile to analyze

        Returns:
            Fake account analysis with indicators
        """
        indicators = {
            'is_likely_fake': False,
            'confidence': 0,
            'red_flags': [],
            'green_flags': [],
        }

        info = profile_data.get('profile_info', {})

        # Red flags
        if info.get('followers', 0) > 10000 and info.get('posts_count', 0) < 10:
            indicators['red_flags'].append('High followers, low content')
            indicators['confidence'] += 20

        if info.get('created_date'):
            # Check if account is very new
            try:
                created = datetime.fromisoformat(info['created_date'])
                if (datetime.now() - created).days < 30:
                    indicators['red_flags'].append('Very new account')
                    indicators['confidence'] += 15
            except:
                pass

        # Check username pattern (random chars = suspicious)
        username = profile_data.get('username', '')
        if len(re.findall(r'\d', username)) > len(username) / 2:
            indicators['red_flags'].append('Username mostly numbers')
            indicators['confidence'] += 10

        # Green flags
        if info.get('verified', False):
            indicators['green_flags'].append('Verified account')
            indicators['confidence'] -= 30

        if info.get('posts_count', 0) > 100:
            indicators['green_flags'].append('Substantial content history')
            indicators['confidence'] -= 15

        # Determine if likely fake
        indicators['is_likely_fake'] = indicators['confidence'] > 40

        return indicators

    def extract_metadata(self, content_url: str) -> Dict:
        """
        Extract metadata from posted content (images, videos, etc.)

        Args:
            content_url: URL to content

        Returns:
            Extracted metadata
        """
        metadata = {
            'url': content_url,
            'content_type': self._identify_content_type(content_url),
            'exif_data': {},
            'timestamps': [],
            'geolocation': None,
        }

        # In real implementation, would download and analyze content
        # For now, provide structure

        return metadata

    def _identify_content_type(self, url: str) -> str:
        """Identify content type from URL"""
        ext = Path(urlparse(url).path).suffix.lower()

        content_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.mp4': 'video/mp4',
            '.mov': 'video/mov',
            '.avi': 'video/avi',
        }

        return content_types.get(ext, 'unknown')

    def track_account_changes(self, profile_snapshots: List[Dict]) -> Dict:
        """
        Track changes to account over time.

        Args:
            profile_snapshots: List of profile snapshots at different times

        Returns:
            Change analysis
        """
        changes = {
            'username_changes': [],
            'profile_picture_changes': 0,
            'bio_changes': 0,
            'location_changes': [],
            'significant_events': [],
        }

        if len(profile_snapshots) < 2:
            return changes

        # Compare snapshots
        for i in range(1, len(profile_snapshots)):
            prev = profile_snapshots[i-1]
            curr = profile_snapshots[i]

            # Check username
            if prev.get('username') != curr.get('username'):
                changes['username_changes'].append({
                    'from': prev.get('username'),
                    'to': curr.get('username'),
                    'date': curr.get('snapshot_date')
                })

            # Check location
            prev_loc = prev.get('profile_info', {}).get('location')
            curr_loc = curr.get('profile_info', {}).get('location')
            if prev_loc != curr_loc:
                changes['location_changes'].append({
                    'from': prev_loc,
                    'to': curr_loc,
                    'date': curr.get('snapshot_date')
                })

        return changes

    def generate_report(self, output_path: str, format: str = 'json') -> None:
        """
        Generate comprehensive OSINT report.

        Args:
            output_path: Path to save report
            format: Report format ('json' or 'html')
        """
        if format == 'json':
            report_data = {
                'generated': datetime.now().isoformat(),
                'profiles_analyzed': len(self.profiles),
                'consolidated_profile': self.consolidated_profile,
                'timeline': self.timeline_events,
                'connections': self.connections,
            }

            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

        elif format == 'html':
            self._generate_html_report(output_path)

        logger.info(f"Report saved to {output_path}")

    def _generate_html_report(self, output_path: str) -> None:
        """Generate HTML format report"""
        profile = self.consolidated_profile

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Social Media OSINT Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .profile-section {{ background: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .identifier {{ background: #3498db; color: white; padding: 5px 10px; margin: 5px; display: inline-block; border-radius: 3px; }}
        .platform {{ background: #27ae60; color: white; padding: 8px 15px; margin: 5px; display: inline-block; border-radius: 3px; }}
        .risk {{ background: #e74c3c; color: white; padding: 5px 10px; margin: 5px; display: inline-block; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .timeline-event {{ border-left: 4px solid #3498db; padding-left: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Social Media OSINT Investigation Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="profile-section">
            <h2>👤 Primary Identifiers</h2>
"""

        # Identifiers
        if profile.get('primary_identifiers'):
            for id_type, values in profile['primary_identifiers'].items():
                if values:
                    html += f"            <p><strong>{id_type.replace('_', ' ').title()}:</strong><br>\n"
                    for value in values:
                        html += f'                <span class="identifier">{value}</span>\n'
                    html += "            </p>\n"

        html += """
        </div>

        <div class="profile-section">
            <h2>🌐 Online Presence</h2>
"""

        # Platforms
        if profile.get('online_presence', {}).get('platforms'):
            for platform, url in profile['online_presence']['platforms'].items():
                html += f'            <span class="platform">{platform.title()}</span>\n'

        html += f"""
            <p><strong>Total Platforms:</strong> {profile.get('online_presence', {}).get('total_platforms', 0)}</p>
        </div>

        <div class="profile-section">
            <h2>📍 Demographics</h2>
"""

        # Demographics
        if profile.get('demographics'):
            for demo_type, values in profile['demographics'].items():
                if values:
                    html += f"            <p><strong>{demo_type.title()}:</strong> {', '.join(values)}</p>\n"

        html += """
        </div>

        <div class="profile-section">
            <h2>📊 Behavioral Analysis</h2>
"""

        # Behavioral
        if profile.get('behavioral_analysis'):
            behavior = profile['behavioral_analysis']
            html += f"            <p><strong>Total Connections:</strong> {behavior.get('connections_count', 0)}</p>\n"

            if behavior.get('interests'):
                html += "            <p><strong>Interests:</strong> " + ', '.join(behavior['interests'][:10]) + "</p>\n"

        html += """
        </div>
"""

        # Risk indicators
        if profile.get('risk_indicators'):
            html += """
        <div class="profile-section">
            <h2>⚠️ Risk Indicators</h2>
"""
            for risk in profile['risk_indicators']:
                html += f'            <span class="risk">{risk}</span>\n'
            html += "        </div>\n"

        html += """
    </div>
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html)


def main():
    """Example usage of ProfileAnalyzer"""
    import argparse

    parser = argparse.ArgumentParser(description='Social Media Profile Analyzer')
    parser.add_argument('--username', required=True, help='Username to investigate')
    parser.add_argument('--platforms', nargs='+', help='Platforms to check')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--format', choices=['json', 'html'], default='html', help='Report format')

    args = parser.parse_args()

    analyzer = ProfileAnalyzer()

    # Analyze username across platforms
    results = analyzer.analyze_username(args.username, args.platforms)

    # Build comprehensive profile
    if results['potential_profiles']:
        profile = analyzer.build_comprehensive_profile(results['potential_profiles'])

    analyzer.generate_report(args.output, args.format)

    print(f"\n✓ OSINT Analysis Complete")
    print(f"  Platforms found: {len(results['platforms_found'])}")
    print(f"  Report saved to: {args.output}")


if __name__ == '__main__':
    main()
