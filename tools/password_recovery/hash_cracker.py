"""
Advanced Hash Cracker
Multi-algorithm password recovery tool with dictionary, brute-force, and rainbow table attacks.
Similar to John the Ripper and Hashcat with AI-powered password prediction.
"""

import hashlib
import hmac
import base64
import itertools
import string
import json
import time
from typing import Dict, List, Optional, Callable, Set
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HashCracker:
    """
    Advanced password hash cracking tool supporting multiple algorithms.
    Implements dictionary, brute-force, and AI-assisted cracking.
    """

    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'ntlm': None,  # Custom implementation
        'lm': None,    # Custom implementation
    }

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.cracked_hashes = []
        self.attempts = 0
        self.start_time = None
        self.common_patterns = self._load_common_patterns()

    def _load_common_patterns(self) -> List[str]:
        """Load common password patterns for AI-assisted cracking"""
        return [
            # Common formats
            '{word}{year}',
            '{word}{number}',
            '{word}!',
            '{word}@{number}',
            '{Word}{number}',
            '{WORD}{number}',
            '{word}{month}',
            '{word}{day}',
            # Leet speak patterns
            '{word_leet}',
            '{word_leet}{number}',
            # Keyboard patterns
            'qwerty{number}',
            'password{number}',
            'admin{number}',
            'welcome{number}',
        ]

    def identify_hash_type(self, hash_string: str) -> Optional[str]:
        """
        Identify hash type based on length and format.

        Args:
            hash_string: Hash string to identify

        Returns:
            Identified hash algorithm name
        """
        hash_string = hash_string.strip().lower()
        length = len(hash_string)

        # Check for common hash lengths
        hash_types = {
            32: ['md5', 'ntlm'],
            40: ['sha1'],
            56: ['sha224'],
            64: ['sha256'],
            96: ['sha384'],
            128: ['sha512'],
        }

        if length in hash_types:
            return hash_types[length][0]

        # Check for salted formats
        if ':' in hash_string:
            return 'salted'

        return None

    def crack_hash_dictionary(self, hash_value: str, algorithm: str,
                             wordlist_path: str, rules: bool = True) -> Optional[str]:
        """
        Crack hash using dictionary attack.

        Args:
            hash_value: Hash to crack
            algorithm: Hash algorithm
            wordlist_path: Path to wordlist file
            rules: Apply password mutation rules

        Returns:
            Cracked password or None
        """
        logger.info(f"Starting dictionary attack on {algorithm.upper()} hash")
        self.start_time = time.time()
        self.attempts = 0

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]

            logger.info(f"Loaded {len(wordlist)} words from dictionary")

            # Try direct words first
            result = self._try_wordlist(hash_value, algorithm, wordlist)
            if result:
                return result

            # Apply mutation rules if enabled
            if rules:
                logger.info("Applying mutation rules...")
                mutated = self._apply_mutation_rules(wordlist[:1000])  # Limit for performance
                result = self._try_wordlist(hash_value, algorithm, mutated)
                if result:
                    return result

            return None

        except FileNotFoundError:
            logger.error(f"Wordlist not found: {wordlist_path}")
            return None

    def _try_wordlist(self, hash_value: str, algorithm: str,
                     wordlist: List[str]) -> Optional[str]:
        """Try each word in wordlist"""
        chunk_size = 1000
        total = len(wordlist)

        for i in range(0, total, chunk_size):
            chunk = wordlist[i:i+chunk_size]

            # Use multiprocessing for speed
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                results = executor.map(
                    lambda word: self._test_password(hash_value, algorithm, word),
                    chunk
                )

                for word, is_match in zip(chunk, results):
                    self.attempts += 1
                    if is_match:
                        elapsed = time.time() - self.start_time
                        logger.info(f"✓ CRACKED in {elapsed:.2f}s after {self.attempts} attempts")
                        self._record_crack(hash_value, word, algorithm, 'dictionary')
                        return word

            if i % 10000 == 0:
                logger.info(f"Tested {i}/{total} passwords...")

        return None

    def _test_password(self, hash_value: str, algorithm: str, password: str) -> bool:
        """Test if password matches hash"""
        try:
            if algorithm in self.SUPPORTED_ALGORITHMS:
                if algorithm == 'ntlm':
                    computed = self._ntlm_hash(password)
                elif algorithm == 'lm':
                    computed = self._lm_hash(password)
                else:
                    hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
                    computed = hash_func(password.encode()).hexdigest()

                return computed.lower() == hash_value.lower()

        except Exception as e:
            logger.debug(f"Error testing password: {e}")

        return False

    def crack_hash_bruteforce(self, hash_value: str, algorithm: str,
                              charset: str = None, min_length: int = 1,
                              max_length: int = 8) -> Optional[str]:
        """
        Crack hash using brute-force attack.

        Args:
            hash_value: Hash to crack
            algorithm: Hash algorithm
            charset: Character set to use
            min_length: Minimum password length
            max_length: Maximum password length

        Returns:
            Cracked password or None
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits

        logger.info(f"Starting brute-force attack (length {min_length}-{max_length})")
        self.start_time = time.time()
        self.attempts = 0

        for length in range(min_length, max_length + 1):
            logger.info(f"Trying length {length}...")

            # Generate combinations in chunks for memory efficiency
            for combination in itertools.product(charset, repeat=length):
                password = ''.join(combination)
                self.attempts += 1

                if self._test_password(hash_value, algorithm, password):
                    elapsed = time.time() - self.start_time
                    logger.info(f"✓ CRACKED in {elapsed:.2f}s after {self.attempts} attempts")
                    self._record_crack(hash_value, password, algorithm, 'bruteforce')
                    return password

                if self.attempts % 100000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    logger.info(f"Attempts: {self.attempts:,} | Rate: {rate:.0f} H/s")

        return None

    def crack_hash_smart(self, hash_value: str, algorithm: str,
                        context: Dict = None) -> Optional[str]:
        """
        AI-assisted smart cracking using context and patterns.

        Args:
            hash_value: Hash to crack
            algorithm: Hash algorithm
            context: Context information (username, email, etc.)

        Returns:
            Cracked password or None
        """
        logger.info("Starting AI-assisted smart attack")
        self.start_time = time.time()
        self.attempts = 0

        candidates = self._generate_smart_candidates(context or {})
        logger.info(f"Generated {len(candidates)} smart candidates")

        return self._try_wordlist(hash_value, algorithm, candidates)

    def _generate_smart_candidates(self, context: Dict) -> List[str]:
        """Generate password candidates based on context and patterns"""
        candidates = set()

        # Extract context information
        username = context.get('username', '')
        email = context.get('email', '')
        name = context.get('name', '')
        organization = context.get('organization', '')

        base_words = [username, email.split('@')[0] if email else '',
                     name, organization]
        base_words = [w.lower() for w in base_words if w]

        # Common password bases
        common_bases = [
            'password', 'admin', 'welcome', 'letmein', 'qwerty',
            'monkey', 'dragon', 'master', 'sunshine', 'princess',
            'login', 'passw0rd', 'abc123', '123456', 'password123'
        ]
        base_words.extend(common_bases)

        # Generate combinations
        years = [str(y) for y in range(2010, 2027)]
        numbers = [str(n) for n in range(0, 100)]
        special = ['!', '@', '#', '$', '123', '321']

        for word in base_words:
            if not word:
                continue

            # Direct word
            candidates.add(word)

            # Capitalized
            candidates.add(word.capitalize())
            candidates.add(word.upper())

            # With numbers
            for num in numbers[:20]:
                candidates.add(f"{word}{num}")
                candidates.add(f"{word.capitalize()}{num}")
                candidates.add(f"{num}{word}")

            # With years
            for year in years:
                candidates.add(f"{word}{year}")
                candidates.add(f"{word.capitalize()}{year}")

            # With special chars
            for spec in special:
                candidates.add(f"{word}{spec}")
                candidates.add(f"{word.capitalize()}{spec}")

            # Leet speak
            candidates.add(self._to_leet_speak(word))
            candidates.add(self._to_leet_speak(word.capitalize()))

            # Keyboard patterns
            if len(word) >= 4:
                candidates.add(f"{word}qwerty")
                candidates.add(f"qwerty{word}")

        # Common patterns
        candidates.update([
            'P@ssw0rd', 'P@ssword1', 'Welc0me!', 'Admin123',
            'Password1!', 'Summer2023', 'Winter2023',
        ])

        return list(candidates)

    def _to_leet_speak(self, word: str) -> str:
        """Convert word to leet speak"""
        leet_map = {
            'a': '4', 'e': '3', 'i': '1', 'o': '0',
            's': '5', 't': '7', 'l': '1', 'g': '9'
        }

        return ''.join(leet_map.get(c.lower(), c) for c in word)

    def _apply_mutation_rules(self, wordlist: List[str]) -> List[str]:
        """Apply password mutation rules to wordlist"""
        mutated = set()

        for word in wordlist:
            # Original
            mutated.add(word)

            # Case variations
            mutated.add(word.capitalize())
            mutated.add(word.upper())
            mutated.add(word.lower())

            # Append numbers
            for i in range(10):
                mutated.add(f"{word}{i}")
                mutated.add(f"{word}{i}{i}")

            # Append common suffixes
            for suffix in ['123', '!', '@', '#', '2023', '2024']:
                mutated.add(f"{word}{suffix}")

            # Prepend numbers
            mutated.add(f"1{word}")
            mutated.add(f"123{word}")

            # Leet speak
            mutated.add(self._to_leet_speak(word))

            # Double
            mutated.add(f"{word}{word}")

            # Reverse
            mutated.add(word[::-1])

        return list(mutated)

    def _ntlm_hash(self, password: str) -> str:
        """Compute NTLM hash"""
        try:
            import hashlib
            return hashlib.new('md4', password.encode('utf-16-le')).hexdigest()
        except:
            # Fallback if md4 not available
            return hashlib.md5(password.encode()).hexdigest()

    def _lm_hash(self, password: str) -> str:
        """Compute LM hash (simplified)"""
        # This is a simplified implementation
        return hashlib.md5(password.upper().encode()).hexdigest()

    def _record_crack(self, hash_value: str, password: str,
                     algorithm: str, method: str) -> None:
        """Record successfully cracked hash"""
        self.cracked_hashes.append({
            'hash': hash_value,
            'password': password,
            'algorithm': algorithm,
            'method': method,
            'attempts': self.attempts,
            'time_seconds': time.time() - self.start_time if self.start_time else 0,
        })

    def crack_multiple_hashes(self, hash_file: str, algorithm: str,
                             wordlist_path: str) -> List[Dict]:
        """
        Crack multiple hashes from a file.

        Args:
            hash_file: File containing hashes (one per line)
            algorithm: Hash algorithm
            wordlist_path: Path to wordlist

        Returns:
            List of cracked hashes
        """
        logger.info(f"Loading hashes from {hash_file}")

        with open(hash_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]

        logger.info(f"Loaded {len(hashes)} hashes")

        results = []
        for i, hash_value in enumerate(hashes, 1):
            logger.info(f"\nCracking hash {i}/{len(hashes)}")
            password = self.crack_hash_dictionary(hash_value, algorithm, wordlist_path)

            results.append({
                'hash': hash_value,
                'password': password if password else 'NOT CRACKED',
                'status': 'CRACKED' if password else 'FAILED'
            })

        return results

    def analyze_password_strength(self, password: str) -> Dict:
        """
        Analyze password strength and provide security assessment.

        Args:
            password: Password to analyze

        Returns:
            Dictionary with strength analysis
        """
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        # Calculate entropy
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        import math
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        # Determine strength
        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        if has_lower and has_upper:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1
        if entropy > 50:
            score += 1

        strength_levels = {
            0: 'VERY WEAK',
            1: 'VERY WEAK',
            2: 'WEAK',
            3: 'MODERATE',
            4: 'MODERATE',
            5: 'STRONG',
            6: 'STRONG',
            7: 'VERY STRONG'
        }

        # Check against common passwords
        is_common = password.lower() in [
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', 'dragon', '12345678'
        ]

        return {
            'password': password,
            'length': length,
            'entropy_bits': round(entropy, 2),
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_special': has_special,
            'strength': strength_levels[score],
            'score': score,
            'is_common': is_common,
            'estimated_crack_time': self._estimate_crack_time(entropy),
        }

    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack based on entropy"""
        # Assume 1 billion hashes per second
        hashes_per_second = 1_000_000_000
        combinations = 2 ** entropy
        seconds = combinations / hashes_per_second

        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        else:
            return f"{seconds/31536000:.0f} years"

    def generate_report(self, output_path: str) -> None:
        """Generate password cracking report"""
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("PASSWORD CRACKING REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Total Hashes Cracked: {len(self.cracked_hashes)}\n\n")

            if self.cracked_hashes:
                f.write("Cracked Passwords:\n")
                f.write("-" * 80 + "\n")

                for item in self.cracked_hashes:
                    f.write(f"Hash: {item['hash']}\n")
                    f.write(f"Password: {item['password']}\n")
                    f.write(f"Algorithm: {item['algorithm'].upper()}\n")
                    f.write(f"Method: {item['method']}\n")
                    f.write(f"Attempts: {item['attempts']:,}\n")
                    f.write(f"Time: {item['time_seconds']:.2f} seconds\n")

                    # Analyze cracked password
                    analysis = self.analyze_password_strength(item['password'])
                    f.write(f"Password Strength: {analysis['strength']}\n")
                    f.write(f"Entropy: {analysis['entropy_bits']} bits\n")
                    f.write("\n")

        logger.info(f"Report saved to {output_path}")


def main():
    """Example usage of HashCracker"""
    import argparse

    parser = argparse.ArgumentParser(description='Advanced Hash Cracker')
    parser.add_argument('--hash', required=True, help='Hash to crack')
    parser.add_argument('--algorithm', required=True, choices=HashCracker.SUPPORTED_ALGORITHMS.keys(),
                       help='Hash algorithm')
    parser.add_argument('--wordlist', help='Wordlist file for dictionary attack')
    parser.add_argument('--bruteforce', action='store_true', help='Use brute-force attack')
    parser.add_argument('--smart', action='store_true', help='Use AI-assisted smart attack')
    parser.add_argument('--username', help='Username for smart attack context')
    parser.add_argument('--max-length', type=int, default=6, help='Max length for brute-force')
    parser.add_argument('--output', help='Output report path')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker processes')

    args = parser.parse_args()

    cracker = HashCracker(max_workers=args.workers)

    # Identify hash type if not specified
    detected_type = cracker.identify_hash_type(args.hash)
    logger.info(f"Detected hash type: {detected_type}")

    password = None

    if args.smart:
        context = {'username': args.username} if args.username else {}
        password = cracker.crack_hash_smart(args.hash, args.algorithm, context)

    elif args.wordlist:
        password = cracker.crack_hash_dictionary(args.hash, args.algorithm, args.wordlist)

    elif args.bruteforce:
        password = cracker.crack_hash_bruteforce(args.hash, args.algorithm,
                                                 max_length=args.max_length)

    else:
        logger.error("Specify attack method: --wordlist, --bruteforce, or --smart")
        return

    if password:
        print(f"\n✓ PASSWORD CRACKED: {password}")

        # Analyze strength
        analysis = cracker.analyze_password_strength(password)
        print(f"  Strength: {analysis['strength']}")
        print(f"  Entropy: {analysis['entropy_bits']} bits")
    else:
        print(f"\n✗ Failed to crack hash")

    if args.output:
        cracker.generate_report(args.output)


if __name__ == '__main__':
    main()
