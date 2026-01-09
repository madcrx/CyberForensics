"""
Password Analyzer
Analyzes password dumps, identifies patterns, and extracts user information.
"""

import re
import json
import hashlib
from typing import Dict, List, Set, Tuple
from collections import Counter, defaultdict
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PasswordAnalyzer:
    """
    Analyzes password dumps and databases for forensic investigation.
    Extracts patterns, user information, and security insights.
    """

    def __init__(self):
        self.passwords = []
        self.users = []
        self.statistics = {}

    def load_password_dump(self, dump_file: str, format: str = 'auto') -> None:
        """
        Load password dump file.

        Args:
            dump_file: Path to password dump
            format: Format (auto, plain, hash, user:hash, user:pass)
        """
        logger.info(f"Loading password dump: {dump_file}")

        with open(dump_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]

        for line in lines:
            if ':' in line:
                parts = line.split(':', 1)
                self.users.append({
                    'username': parts[0],
                    'credential': parts[1],
                })
            else:
                self.passwords.append(line)

        logger.info(f"Loaded {len(self.users)} user records and {len(self.passwords)} passwords")

    def analyze_patterns(self) -> Dict:
        """
        Analyze password patterns and commonalities.

        Returns:
            Dictionary with pattern analysis
        """
        logger.info("Analyzing password patterns...")

        all_passwords = self.passwords + [u['credential'] for u in self.users
                                         if len(u.get('credential', '')) < 50]

        if not all_passwords:
            return {}

        patterns = {
            'length_distribution': self._analyze_lengths(all_passwords),
            'charset_usage': self._analyze_charset(all_passwords),
            'common_patterns': self._find_common_patterns(all_passwords),
            'top_passwords': self._get_top_passwords(all_passwords),
            'password_masks': self._generate_masks(all_passwords),
            'base_words': self._extract_base_words(all_passwords),
            'years_found': self._extract_years(all_passwords),
            'keyboard_patterns': self._find_keyboard_patterns(all_passwords),
        }

        self.statistics = patterns
        return patterns

    def _analyze_lengths(self, passwords: List[str]) -> Dict:
        """Analyze password length distribution"""
        lengths = Counter(len(p) for p in passwords)

        return {
            'distribution': dict(lengths.most_common(20)),
            'average': sum(len(p) for p in passwords) / len(passwords),
            'min': min(len(p) for p in passwords),
            'max': max(len(p) for p in passwords),
        }

    def _analyze_charset(self, passwords: List[str]) -> Dict:
        """Analyze character set usage"""
        charsets = {
            'lowercase_only': 0,
            'uppercase_only': 0,
            'digits_only': 0,
            'lowercase_digits': 0,
            'mixed_alpha': 0,
            'mixed_alphanumeric': 0,
            'with_special': 0,
        }

        for pwd in passwords:
            has_lower = any(c.islower() for c in pwd)
            has_upper = any(c.isupper() for c in pwd)
            has_digit = any(c.isdigit() for c in pwd)
            has_special = any(not c.isalnum() for c in pwd)

            if pwd.islower():
                charsets['lowercase_only'] += 1
            elif pwd.isupper():
                charsets['uppercase_only'] += 1
            elif pwd.isdigit():
                charsets['digits_only'] += 1
            elif has_lower and has_digit and not has_upper:
                charsets['lowercase_digits'] += 1
            elif has_lower and has_upper and not has_digit:
                charsets['mixed_alpha'] += 1
            elif has_lower and has_upper and has_digit:
                charsets['mixed_alphanumeric'] += 1

            if has_special:
                charsets['with_special'] += 1

        # Convert to percentages
        total = len(passwords)
        return {k: f"{(v/total*100):.1f}%" for k, v in charsets.items()}

    def _find_common_patterns(self, passwords: List[str]) -> List[Dict]:
        """Find common password patterns"""
        patterns = [
            ('Starts with capital', r'^[A-Z]'),
            ('Ends with digit', r'\d$'),
            ('Ends with !', r'!$'),
            ('Contains year', r'19\d{2}|20\d{2}'),
            ('Contains month', r'jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec'),
            ('Only lowercase', r'^[a-z]+$'),
            ('Only digits', r'^\d+$'),
            ('Repeating chars', r'(.)\1{2,}'),
            ('Sequential digits', r'(123|234|345|456|567|678|789|012)'),
            ('Common prefix', r'^(pass|admin|user|test|demo)'),
        ]

        results = []
        for name, pattern in patterns:
            matches = sum(1 for p in passwords if re.search(pattern, p, re.I))
            if matches > 0:
                results.append({
                    'pattern': name,
                    'count': matches,
                    'percentage': f"{(matches/len(passwords)*100):.1f}%"
                })

        return sorted(results, key=lambda x: x['count'], reverse=True)

    def _get_top_passwords(self, passwords: List[str], top_n: int = 20) -> List[Tuple]:
        """Get most common passwords"""
        counter = Counter(passwords)
        return counter.most_common(top_n)

    def _generate_masks(self, passwords: List[str], top_n: int = 20) -> List[Tuple]:
        """
        Generate password masks (e.g., 'Password1' -> '?u?l?l?l?l?l?l?l?d')
        Similar to Hashcat masks
        """
        def password_to_mask(pwd: str) -> str:
            mask = []
            for c in pwd:
                if c.islower():
                    mask.append('?l')
                elif c.isupper():
                    mask.append('?u')
                elif c.isdigit():
                    mask.append('?d')
                else:
                    mask.append('?s')
            return ''.join(mask)

        masks = Counter(password_to_mask(p) for p in passwords)
        return masks.most_common(top_n)

    def _extract_base_words(self, passwords: List[str]) -> List[str]:
        """Extract base words from passwords"""
        # Remove common suffixes/prefixes
        base_words = set()

        for pwd in passwords:
            # Remove trailing digits
            base = re.sub(r'\d+$', '', pwd)
            # Remove trailing special chars
            base = re.sub(r'[!@#$%^&*()_+\-=\[\]{};\':\"\\|,.<>\/?]+$', '', base)

            if len(base) >= 4:
                base_words.add(base.lower())

        # Get most common
        base_counter = Counter()
        for base in base_words:
            base_counter[base] = sum(1 for p in passwords
                                    if base in p.lower())

        return [word for word, count in base_counter.most_common(20)]

    def _extract_years(self, passwords: List[str]) -> List[int]:
        """Extract years found in passwords"""
        years = []
        year_pattern = r'(19\d{2}|20\d{2})'

        for pwd in passwords:
            matches = re.findall(year_pattern, pwd)
            years.extend(int(y) for y in matches)

        if years:
            year_counts = Counter(years)
            return [year for year, count in year_counts.most_common(10)]

        return []

    def _find_keyboard_patterns(self, passwords: List[str]) -> List[str]:
        """Find keyboard walk patterns"""
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', 'qazwsx',
            'qwertyuiop', 'asdfghjkl', '1qaz2wsx', 'zaq12wsx'
        ]

        found = []
        for pattern in keyboard_patterns:
            count = sum(1 for p in passwords if pattern in p.lower())
            if count > 0:
                found.append(f"{pattern} ({count} times)")

        return found

    def identify_users_at_risk(self) -> List[Dict]:
        """
        Identify users with weak passwords.

        Returns:
            List of users with risk assessment
        """
        logger.info("Identifying users at risk...")

        at_risk = []
        weak_passwords = [
            'password', '123456', 'admin', 'welcome', 'letmein',
            'qwerty', 'monkey', 'dragon', '12345678', 'abc123'
        ]

        for user in self.users:
            credential = user.get('credential', '')

            # Check if it looks like a plaintext password
            if len(credential) < 50 and not re.match(r'^[a-f0-9]{32,}$', credential):
                risk_factors = []

                if len(credential) < 8:
                    risk_factors.append('Too short')

                if credential.lower() in weak_passwords:
                    risk_factors.append('Common password')

                if credential.isdigit():
                    risk_factors.append('Only digits')

                if credential.lower() == user['username'].lower():
                    risk_factors.append('Same as username')

                if credential.islower() and credential.isalpha():
                    risk_factors.append('Only lowercase letters')

                if risk_factors:
                    at_risk.append({
                        'username': user['username'],
                        'password': credential,
                        'risk_factors': risk_factors,
                        'risk_level': 'HIGH' if len(risk_factors) >= 2 else 'MEDIUM'
                    })

        return sorted(at_risk, key=lambda x: len(x['risk_factors']), reverse=True)

    def correlate_users(self) -> Dict:
        """
        Correlate users who use the same passwords.
        Useful for identifying shared accounts or password reuse.

        Returns:
            Dictionary mapping passwords to users
        """
        password_users = defaultdict(list)

        for user in self.users:
            credential = user.get('credential', '')
            if credential:
                password_users[credential].append(user['username'])

        # Filter to show only passwords used by multiple users
        shared = {pwd: users for pwd, users in password_users.items()
                 if len(users) > 1}

        return dict(sorted(shared.items(), key=lambda x: len(x[1]), reverse=True))

    def extract_email_addresses(self) -> List[str]:
        """Extract email addresses from usernames"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = []

        for user in self.users:
            username = user.get('username', '')
            if re.match(email_pattern, username):
                emails.append(username)

        return emails

    def extract_domains(self) -> List[Tuple[str, int]]:
        """Extract and count email domains"""
        emails = self.extract_email_addresses()
        domains = [email.split('@')[1] for email in emails if '@' in email]

        return Counter(domains).most_common()

    def generate_wordlist(self, output_path: str, min_frequency: int = 2) -> None:
        """
        Generate custom wordlist from analyzed passwords.

        Args:
            output_path: Path to save wordlist
            min_frequency: Minimum password frequency to include
        """
        all_passwords = self.passwords + [u['credential'] for u in self.users
                                         if len(u.get('credential', '')) < 50]

        password_counts = Counter(all_passwords)
        filtered = [pwd for pwd, count in password_counts.items()
                   if count >= min_frequency]

        with open(output_path, 'w') as f:
            for pwd in sorted(filtered):
                f.write(f"{pwd}\n")

        logger.info(f"Generated wordlist with {len(filtered)} passwords: {output_path}")

    def generate_report(self, output_path: str) -> None:
        """Generate comprehensive password analysis report"""
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("PASSWORD ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Total Passwords Analyzed: {len(self.passwords) + len(self.users)}\n")
            f.write(f"Total Users: {len(self.users)}\n\n")

            if self.statistics:
                # Length distribution
                f.write("PASSWORD LENGTH DISTRIBUTION:\n")
                f.write("-" * 80 + "\n")
                lengths = self.statistics['length_distribution']
                f.write(f"Average Length: {lengths['average']:.1f} characters\n")
                f.write(f"Min Length: {lengths['min']} | Max Length: {lengths['max']}\n\n")

                for length, count in sorted(lengths['distribution'].items()):
                    f.write(f"  Length {length}: {count} passwords\n")
                f.write("\n")

                # Character set usage
                f.write("CHARACTER SET USAGE:\n")
                f.write("-" * 80 + "\n")
                for charset, percentage in self.statistics['charset_usage'].items():
                    f.write(f"  {charset}: {percentage}\n")
                f.write("\n")

                # Common patterns
                f.write("COMMON PATTERNS:\n")
                f.write("-" * 80 + "\n")
                for pattern in self.statistics['common_patterns'][:10]:
                    f.write(f"  {pattern['pattern']}: {pattern['count']} ({pattern['percentage']})\n")
                f.write("\n")

                # Top passwords
                f.write("TOP 20 PASSWORDS:\n")
                f.write("-" * 80 + "\n")
                for pwd, count in self.statistics['top_passwords']:
                    f.write(f"  {pwd}: {count} times\n")
                f.write("\n")

                # Password masks
                f.write("TOP PASSWORD MASKS:\n")
                f.write("-" * 80 + "\n")
                for mask, count in self.statistics['password_masks'][:10]:
                    f.write(f"  {mask}: {count} passwords\n")
                f.write("\n")

                # Base words
                f.write("COMMON BASE WORDS:\n")
                f.write("-" * 80 + "\n")
                for word in self.statistics['base_words']:
                    f.write(f"  {word}\n")
                f.write("\n")

                # Years
                if self.statistics['years_found']:
                    f.write("YEARS FOUND IN PASSWORDS:\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"  {', '.join(str(y) for y in self.statistics['years_found'])}\n\n")

            # Users at risk
            at_risk = self.identify_users_at_risk()
            if at_risk:
                f.write("USERS AT RISK (Weak Passwords):\n")
                f.write("-" * 80 + "\n")
                for user in at_risk[:20]:
                    f.write(f"  Username: {user['username']}\n")
                    f.write(f"  Password: {user['password']}\n")
                    f.write(f"  Risk Level: {user['risk_level']}\n")
                    f.write(f"  Risk Factors: {', '.join(user['risk_factors'])}\n\n")

            # Shared passwords
            shared = self.correlate_users()
            if shared:
                f.write("SHARED PASSWORDS (Password Reuse):\n")
                f.write("-" * 80 + "\n")
                for pwd, users in list(shared.items())[:10]:
                    f.write(f"  Password: {pwd}\n")
                    f.write(f"  Users ({len(users)}): {', '.join(users)}\n\n")

            # Email domains
            domains = self.extract_domains()
            if domains:
                f.write("EMAIL DOMAINS:\n")
                f.write("-" * 80 + "\n")
                for domain, count in domains[:10]:
                    f.write(f"  {domain}: {count} users\n")
                f.write("\n")

        logger.info(f"Report saved to {output_path}")


def main():
    """Example usage of PasswordAnalyzer"""
    import argparse

    parser = argparse.ArgumentParser(description='Password Analyzer')
    parser.add_argument('--dump', required=True, help='Password dump file')
    parser.add_argument('--format', default='auto', help='Dump format')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--wordlist', help='Generate custom wordlist')

    args = parser.parse_args()

    analyzer = PasswordAnalyzer()
    analyzer.load_password_dump(args.dump, args.format)
    analyzer.analyze_patterns()
    analyzer.generate_report(args.output)

    if args.wordlist:
        analyzer.generate_wordlist(args.wordlist)

    print(f"\n✓ Analysis complete")
    print(f"  Report saved to: {args.output}")


if __name__ == '__main__':
    main()
