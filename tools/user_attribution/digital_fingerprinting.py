"""
Digital Fingerprinting
Creates unique digital fingerprints of users based on their artifacts and behavior.
"""

import hashlib
import json
from typing import Dict, List
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DigitalFingerprinting:
    """
    Create unique digital fingerprints for user identification.
    """

    def __init__(self):
        self.fingerprints = {}

    def create_fingerprint(self, user_id: str, artifacts: Dict) -> str:
        """
        Create unique fingerprint from user artifacts.

        Args:
            user_id: User identifier
            artifacts: Dictionary of user artifacts

        Returns:
            Fingerprint hash
        """
        # Combine various artifacts
        fingerprint_data = {
            'browser_fingerprint': self._create_browser_fingerprint(artifacts.get('browser', {})),
            'network_fingerprint': self._create_network_fingerprint(artifacts.get('network', {})),
            'behavior_fingerprint': self._create_behavior_fingerprint(artifacts.get('behavior', {})),
            'system_fingerprint': self._create_system_fingerprint(artifacts.get('system', {})),
        }

        # Create composite hash
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()

        self.fingerprints[user_id] = {
            'hash': fingerprint_hash,
            'data': fingerprint_data,
            'artifacts': artifacts
        }

        return fingerprint_hash

    def _create_browser_fingerprint(self, browser_data: Dict) -> str:
        """Create fingerprint from browser artifacts"""
        components = [
            str(browser_data.get('user_agent', '')),
            str(browser_data.get('screen_resolution', '')),
            str(browser_data.get('timezone', '')),
            str(browser_data.get('plugins', [])),
            str(browser_data.get('fonts', [])),
        ]

        return hashlib.md5('|'.join(components).encode()).hexdigest()

    def _create_network_fingerprint(self, network_data: Dict) -> str:
        """Create fingerprint from network behavior"""
        components = [
            str(network_data.get('typical_ips', [])),
            str(network_data.get('port_patterns', [])),
            str(network_data.get('protocols_used', [])),
        ]

        return hashlib.md5('|'.join(components).encode()).hexdigest()

    def _create_behavior_fingerprint(self, behavior_data: Dict) -> str:
        """Create fingerprint from behavioral patterns"""
        components = [
            str(behavior_data.get('typing_speed', '')),
            str(behavior_data.get('mouse_patterns', '')),
            str(behavior_data.get('activity_hours', [])),
        ]

        return hashlib.md5('|'.join(components).encode()).hexdigest()

    def _create_system_fingerprint(self, system_data: Dict) -> str:
        """Create fingerprint from system artifacts"""
        components = [
            str(system_data.get('os_version', '')),
            str(system_data.get('hardware_id', '')),
            str(system_data.get('installed_software', [])),
        ]

        return hashlib.md5('|'.join(components).encode()).hexdigest()

    def compare_fingerprints(self, fp1: str, fp2: str) -> float:
        """
        Compare two fingerprints and return similarity score.

        Returns:
            Similarity score (0.0-1.0)
        """
        if fp1 == fp2:
            return 1.0

        # Compare individual components
        if fp1 in self.fingerprints and fp2 in self.fingerprints:
            data1 = self.fingerprints[fp1]['data']
            data2 = self.fingerprints[fp2]['data']

            matches = sum(1 for k in data1 if data1[k] == data2.get(k))
            total = len(data1)

            return matches / total if total > 0 else 0.0

        return 0.0


if __name__ == '__main__':
    print("Digital Fingerprinting Module")
