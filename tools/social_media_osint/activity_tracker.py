"""
Activity Tracker
Monitors and analyzes user activity patterns across social media platforms.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ActivityTracker:
    """
    Track and analyze user activity patterns for behavioral profiling.
    """

    def __init__(self):
        self.activities = []
        self.patterns = {}

    def load_activities(self, activities_file: str) -> None:
        """Load activity data from JSON file"""
        with open(activities_file, 'r') as f:
            self.activities = json.load(f)
        logger.info(f"Loaded {len(self.activities)} activities")

    def analyze_activity_patterns(self) -> Dict:
        """Analyze temporal and behavioral patterns"""
        patterns = {
            'hourly_distribution': self._analyze_hourly_activity(),
            'daily_distribution': self._analyze_daily_activity(),
            'activity_bursts': self._detect_activity_bursts(),
            'content_patterns': self._analyze_content_patterns(),
            'engagement_analysis': self._analyze_engagement(),
        }

        self.patterns = patterns
        return patterns

    def _analyze_hourly_activity(self) -> Dict:
        """Analyze activity by hour of day"""
        hourly = defaultdict(int)

        for activity in self.activities:
            try:
                timestamp = datetime.fromisoformat(activity.get('timestamp', ''))
                hourly[timestamp.hour] += 1
            except:
                continue

        # Determine most active hours
        most_active = sorted(hourly.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            'distribution': dict(hourly),
            'most_active_hours': [h for h, _ in most_active],
            'likely_timezone': self._estimate_timezone(hourly),
        }

    def _analyze_daily_activity(self) -> Dict:
        """Analyze activity by day of week"""
        daily = defaultdict(int)

        for activity in self.activities:
            try:
                timestamp = datetime.fromisoformat(activity.get('timestamp', ''))
                daily[timestamp.strftime('%A')] += 1
            except:
                continue

        return dict(daily)

    def _estimate_timezone(self, hourly_dist: Dict) -> str:
        """Estimate user's timezone based on activity patterns"""
        if not hourly_dist:
            return "Unknown"

        # Find peak activity hour
        peak_hour = max(hourly_dist, key=hourly_dist.get)

        # Assume peak activity is typically 19:00-21:00 local time
        if 19 <= peak_hour <= 21:
            return "UTC+0 (likely)"
        elif 0 <= peak_hour <= 3:
            return "UTC+4 to UTC+6 (likely)"
        elif 4 <= peak_hour <= 8:
            return "UTC+8 to UTC+12 (likely)"
        else:
            return "UTC-8 to UTC-4 (likely)"

    def _detect_activity_bursts(self) -> List[Dict]:
        """Detect unusual bursts of activity"""
        bursts = []
        # Sort activities by timestamp
        sorted_activities = sorted(
            [a for a in self.activities if 'timestamp' in a],
            key=lambda x: x['timestamp']
        )

        # Group activities by time windows (15 minutes)
        window_size = timedelta(minutes=15)
        windows = defaultdict(list)

        for activity in sorted_activities:
            try:
                timestamp = datetime.fromisoformat(activity['timestamp'])
                window_key = timestamp.replace(minute=timestamp.minute // 15 * 15, second=0, microsecond=0)
                windows[window_key].append(activity)
            except:
                continue

        # Find windows with unusually high activity
        avg_activity = len(sorted_activities) / len(windows) if windows else 0

        for window_time, activities in windows.items():
            if len(activities) > avg_activity * 3:  # 3x average = burst
                bursts.append({
                    'timestamp': window_time.isoformat(),
                    'activity_count': len(activities),
                    'above_average': f"{(len(activities) / avg_activity):.1f}x"
                })

        return sorted(bursts, key=lambda x: x['activity_count'], reverse=True)[:10]

    def _analyze_content_patterns(self) -> Dict:
        """Analyze patterns in posted content"""
        patterns = {
            'post_types': Counter(),
            'common_keywords': Counter(),
            'hashtags_used': Counter(),
            'media_types': Counter(),
        }

        for activity in self.activities:
            activity_type = activity.get('type', 'unknown')
            patterns['post_types'][activity_type] += 1

            content = activity.get('content', '')
            if content:
                # Extract hashtags
                hashtags = [word for word in content.split() if word.startswith('#')]
                patterns['hashtags_used'].update(hashtags)

                # Extract keywords (simplified)
                words = content.lower().split()
                keywords = [w for w in words if len(w) > 5 and not w.startswith('#')]
                patterns['common_keywords'].update(keywords[:10])

            media_type = activity.get('media_type')
            if media_type:
                patterns['media_types'][media_type] += 1

        return {
            'post_types': dict(patterns['post_types'].most_common(10)),
            'top_keywords': dict(patterns['common_keywords'].most_common(20)),
            'top_hashtags': dict(patterns['hashtags_used'].most_common(20)),
            'media_types': dict(patterns['media_types']),
        }

    def _analyze_engagement(self) -> Dict:
        """Analyze engagement metrics"""
        total_likes = sum(a.get('likes', 0) for a in self.activities)
        total_shares = sum(a.get('shares', 0) for a in self.activities)
        total_comments = sum(a.get('comments', 0) for a in self.activities)

        post_count = len([a for a in self.activities if a.get('type') == 'post'])

        return {
            'total_likes': total_likes,
            'total_shares': total_shares,
            'total_comments': total_comments,
            'avg_likes_per_post': total_likes / post_count if post_count else 0,
            'avg_shares_per_post': total_shares / post_count if post_count else 0,
            'engagement_rate': (total_likes + total_shares + total_comments) / post_count if post_count else 0,
        }

    def identify_behavioral_anomalies(self) -> List[Dict]:
        """Identify unusual behavioral patterns"""
        anomalies = []

        # Check for sudden activity spikes
        bursts = self._detect_activity_bursts()
        if bursts:
            anomalies.append({
                'type': 'ACTIVITY_BURST',
                'severity': 'MEDIUM',
                'description': f'Detected {len(bursts)} periods of unusually high activity',
                'details': bursts[:3]
            })

        # Check for bot-like behavior
        hourly = self.patterns.get('hourly_distribution', {}).get('distribution', {})
        if hourly:
            activity_spread = len([h for h, count in hourly.items() if count > 0])
            if activity_spread >= 20:  # Active 20+ hours per day
                anomalies.append({
                    'type': 'BOT_LIKE_BEHAVIOR',
                    'severity': 'HIGH',
                    'description': 'Account shows activity across unusual number of hours',
                    'details': f'Active {activity_spread}/24 hours'
                })

        return anomalies

    def generate_report(self, output_path: str) -> None:
        """Generate activity tracking report"""
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("ACTIVITY TRACKING REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Total Activities Tracked: {len(self.activities)}\n\n")

            if self.patterns:
                # Hourly distribution
                hourly = self.patterns.get('hourly_distribution', {})
                f.write("HOURLY ACTIVITY DISTRIBUTION:\n")
                f.write(f"Most Active Hours: {', '.join(map(str, hourly.get('most_active_hours', [])))}\n")
                f.write(f"Estimated Timezone: {hourly.get('likely_timezone', 'Unknown')}\n\n")

                # Content patterns
                content = self.patterns.get('content_patterns', {})
                f.write("TOP KEYWORDS:\n")
                for keyword, count in list(content.get('top_keywords', {}).items())[:10]:
                    f.write(f"  {keyword}: {count}\n")
                f.write("\n")

                f.write("TOP HASHTAGS:\n")
                for hashtag, count in list(content.get('top_hashtags', {}).items())[:10]:
                    f.write(f"  {hashtag}: {count}\n")
                f.write("\n")

            # Anomalies
            anomalies = self.identify_behavioral_anomalies()
            if anomalies:
                f.write("BEHAVIORAL ANOMALIES:\n")
                for anomaly in anomalies:
                    f.write(f"  [{anomaly['severity']}] {anomaly['type']}\n")
                    f.write(f"  {anomaly['description']}\n\n")

        logger.info(f"Report saved to {output_path}")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Social Media Activity Tracker')
    parser.add_argument('--activities', required=True, help='Activities JSON file')
    parser.add_argument('--output', required=True, help='Output report path')

    args = parser.parse_args()

    tracker = ActivityTracker()
    tracker.load_activities(args.activities)
    tracker.analyze_activity_patterns()
    tracker.generate_report(args.output)

    print(f"\n✓ Activity analysis complete")
