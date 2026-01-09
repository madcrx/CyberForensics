"""
Email Intelligence Tool
Advanced email header analysis, sender tracking, and email forensics.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, List, Optional
from datetime import datetime
import json
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailIntelligence:
    """
    Comprehensive email analysis tool for forensic investigations.
    Analyzes email headers, traces sender path, and extracts intelligence.
    """

    def __init__(self):
        self.analyzed_emails = []

    def analyze_email_file(self, email_path: str) -> Dict:
        """
        Analyze email from .eml file.

        Args:
            email_path: Path to .eml file

        Returns:
            Dictionary with email analysis
        """
        logger.info(f"Analyzing email: {email_path}")

        try:
            with open(email_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)

            return self.analyze_email_message(msg)

        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            return {'error': str(e)}

    def analyze_email_raw(self, raw_email: str) -> Dict:
        """
        Analyze email from raw text/headers.

        Args:
            raw_email: Raw email text including headers

        Returns:
            Dictionary with email analysis
        """
        parser = Parser(policy=policy.default)
        msg = parser.parsestr(raw_email)

        return self.analyze_email_message(msg)

    def analyze_email_message(self, msg: email.message.Message) -> Dict:
        """
        Analyze email message object.

        Args:
            msg: Email message object

        Returns:
            Complete email analysis
        """
        analysis = {
            'basic_info': self._extract_basic_info(msg),
            'sender_info': self._analyze_sender(msg),
            'recipient_info': self._extract_recipients(msg),
            'headers': self._extract_headers(msg),
            'route_analysis': self._trace_email_route(msg),
            'authentication': self._check_authentication(msg),
            'attachments': self._analyze_attachments(msg),
            'content_analysis': self._analyze_content(msg),
            'suspicious_indicators': [],
            'risk_score': 0,
        }

        # Detect suspicious patterns
        analysis['suspicious_indicators'] = self._detect_suspicious_patterns(analysis)

        # Calculate risk score
        analysis['risk_score'] = self._calculate_email_risk(analysis)

        self.analyzed_emails.append(analysis)

        return analysis

    def _extract_basic_info(self, msg: email.message.Message) -> Dict:
        """Extract basic email information"""
        return {
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'in_reply_to': msg.get('In-Reply-To', ''),
            'references': msg.get('References', ''),
        }

    def _analyze_sender(self, msg: email.message.Message) -> Dict:
        """Analyze sender information"""
        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        reply_to = msg.get('Reply-To', '')

        # Parse From header
        from_address, from_name = self._parse_email_address(from_header)

        sender_info = {
            'from_address': from_address,
            'from_name': from_name,
            'from_header_raw': from_header,
            'return_path': return_path,
            'reply_to': reply_to,
            'sender_domain': from_address.split('@')[1] if '@' in from_address else '',
            'envelope_sender': msg.get('Envelope-From', ''),
        }

        # Check for spoofing indicators
        sender_info['spoofing_indicators'] = self._check_sender_spoofing(sender_info)

        return sender_info

    def _parse_email_address(self, header_value: str) -> tuple:
        """Parse email address from header"""
        # Pattern: "Name" <email@domain.com> or email@domain.com
        pattern = r'(?:"?([^"]*)"?\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?'
        match = re.search(pattern, header_value)

        if match:
            name = match.group(1) or ''
            address = match.group(2)
            return address.strip(), name.strip()

        return header_value.strip(), ''

    def _extract_recipients(self, msg: email.message.Message) -> Dict:
        """Extract recipient information"""
        to_header = msg.get('To', '')
        cc_header = msg.get('Cc', '')
        bcc_header = msg.get('Bcc', '')

        return {
            'to': self._parse_recipients_list(to_header),
            'cc': self._parse_recipients_list(cc_header),
            'bcc': self._parse_recipients_list(bcc_header),
            'total_recipients': len(self._parse_recipients_list(to_header)) +
                              len(self._parse_recipients_list(cc_header)) +
                              len(self._parse_recipients_list(bcc_header)),
        }

    def _parse_recipients_list(self, recipients_str: str) -> List[str]:
        """Parse comma-separated recipient list"""
        if not recipients_str:
            return []

        recipients = []
        for recipient in recipients_str.split(','):
            address, _ = self._parse_email_address(recipient)
            if address:
                recipients.append(address)

        return recipients

    def _extract_headers(self, msg: email.message.Message) -> Dict:
        """Extract all email headers"""
        headers = {}

        for key, value in msg.items():
            if key not in headers:
                headers[key] = value
            else:
                # Multiple instances of same header
                if isinstance(headers[key], list):
                    headers[key].append(value)
                else:
                    headers[key] = [headers[key], value]

        return headers

    def _trace_email_route(self, msg: email.message.Message) -> Dict:
        """
        Trace the path email took through mail servers.
        Analyzes Received headers to build hop-by-hop path.
        """
        received_headers = []

        # Get all Received headers (in reverse order - newest first)
        for header_name, header_value in msg.items():
            if header_name.lower() == 'received':
                received_headers.append(header_value)

        # Parse Received headers
        hops = []
        for i, received in enumerate(reversed(received_headers), 1):
            hop = self._parse_received_header(received, i)
            hops.append(hop)

        return {
            'total_hops': len(hops),
            'hops': hops,
            'originating_ip': hops[0].get('from_ip') if hops else None,
            'first_server': hops[0].get('from_host') if hops else None,
        }

    def _parse_received_header(self, received: str, hop_number: int) -> Dict:
        """Parse a single Received header"""
        hop = {
            'hop_number': hop_number,
            'raw': received,
            'from_host': None,
            'from_ip': None,
            'by_host': None,
            'timestamp': None,
        }

        # Extract from host
        from_match = re.search(r'from\s+([^\s\[]+)', received)
        if from_match:
            hop['from_host'] = from_match.group(1)

        # Extract from IP
        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
        if ip_match:
            hop['from_ip'] = ip_match.group(1)

        # Extract by host
        by_match = re.search(r'by\s+([^\s]+)', received)
        if by_match:
            hop['by_host'] = by_match.group(1)

        # Extract timestamp
        date_match = re.search(r';\s*(.+)$', received)
        if date_match:
            hop['timestamp'] = date_match.group(1).strip()

        return hop

    def _check_authentication(self, msg: email.message.Message) -> Dict:
        """Check email authentication (SPF, DKIM, DMARC)"""
        auth = {
            'spf': self._check_spf(msg),
            'dkim': self._check_dkim(msg),
            'dmarc': self._check_dmarc(msg),
            'authentication_results': msg.get('Authentication-Results', ''),
        }

        # Overall authentication status
        auth['is_authenticated'] = (
            auth['spf'].get('pass', False) and
            auth['dkim'].get('pass', False)
        )

        return auth

    def _check_spf(self, msg: email.message.Message) -> Dict:
        """Check SPF authentication"""
        received_spf = msg.get('Received-SPF', '')
        auth_results = msg.get('Authentication-Results', '')

        spf_pass = 'pass' in received_spf.lower() or 'spf=pass' in auth_results.lower()

        return {
            'pass': spf_pass,
            'header': received_spf,
        }

    def _check_dkim(self, msg: email.message.Message) -> Dict:
        """Check DKIM signature"""
        dkim_signature = msg.get('DKIM-Signature', '')
        auth_results = msg.get('Authentication-Results', '')

        dkim_pass = 'dkim=pass' in auth_results.lower()

        return {
            'pass': dkim_pass,
            'signature': dkim_signature,
        }

    def _check_dmarc(self, msg: email.message.Message) -> Dict:
        """Check DMARC policy"""
        auth_results = msg.get('Authentication-Results', '')

        dmarc_pass = 'dmarc=pass' in auth_results.lower()

        return {
            'pass': dmarc_pass,
        }

    def _analyze_attachments(self, msg: email.message.Message) -> List[Dict]:
        """Analyze email attachments"""
        attachments = []

        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            if part.get('Content-Disposition') is None:
                continue

            filename = part.get_filename()
            if filename:
                attachment = {
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'size': len(part.get_payload(decode=True) or b''),
                    'is_suspicious': self._is_suspicious_attachment(filename),
                }

                attachments.append(attachment)

        return attachments

    def _is_suspicious_attachment(self, filename: str) -> bool:
        """Check if attachment filename is suspicious"""
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.zip', '.rar', '.7z'
        ]

        filename_lower = filename.lower()

        for ext in suspicious_extensions:
            if filename_lower.endswith(ext):
                return True

        # Check for double extensions
        if filename_lower.count('.') > 1:
            return True

        return False

    def _analyze_content(self, msg: email.message.Message) -> Dict:
        """Analyze email content"""
        # Get email body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        # Extract URLs
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body)

        # Extract phone numbers
        phones = re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', body)

        # Extract email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', body)

        return {
            'body_length': len(body),
            'urls': urls[:10],  # First 10 URLs
            'url_count': len(urls),
            'phone_numbers': phones,
            'email_addresses': list(set(emails)),
            'has_html': msg.get_content_type() == 'text/html',
        }

    def _check_sender_spoofing(self, sender_info: Dict) -> List[str]:
        """Check for sender spoofing indicators"""
        indicators = []

        # Check if From and Return-Path differ
        from_addr = sender_info.get('from_address', '')
        return_path = sender_info.get('return_path', '')

        if return_path and from_addr != return_path.strip('<>'):
            indicators.append('From/Return-Path mismatch')

        # Check for Reply-To spoofing
        reply_to = sender_info.get('reply_to', '')
        if reply_to and reply_to != from_addr:
            indicators.append('Reply-To differs from From')

        # Check for suspicious display name
        from_name = sender_info.get('from_name', '')
        if from_name and re.search(r'@', from_name):
            indicators.append('Email address in display name')

        return indicators

    def _detect_suspicious_patterns(self, analysis: Dict) -> List[Dict]:
        """Detect suspicious patterns in email"""
        indicators = []

        # Check authentication
        if not analysis['authentication']['is_authenticated']:
            indicators.append({
                'type': 'AUTHENTICATION_FAILURE',
                'severity': 'HIGH',
                'description': 'Email failed SPF/DKIM authentication',
            })

        # Check for spoofing
        spoofing = analysis['sender_info'].get('spoofing_indicators', [])
        if spoofing:
            indicators.append({
                'type': 'SENDER_SPOOFING',
                'severity': 'CRITICAL',
                'description': f"Spoofing indicators: {', '.join(spoofing)}",
            })

        # Check for suspicious attachments
        for attachment in analysis['attachments']:
            if attachment.get('is_suspicious'):
                indicators.append({
                    'type': 'SUSPICIOUS_ATTACHMENT',
                    'severity': 'HIGH',
                    'description': f"Suspicious attachment: {attachment['filename']}",
                })

        # Check for phishing indicators
        content = analysis['content_analysis']
        if content.get('url_count', 0) > 5:
            indicators.append({
                'type': 'EXCESSIVE_URLS',
                'severity': 'MEDIUM',
                'description': f"Email contains {content['url_count']} URLs",
            })

        return indicators

    def _calculate_email_risk(self, analysis: Dict) -> int:
        """Calculate email risk score (0-100)"""
        score = 0

        # Authentication failures
        if not analysis['authentication']['is_authenticated']:
            score += 30

        # Spoofing indicators
        if analysis['sender_info'].get('spoofing_indicators'):
            score += 25

        # Suspicious attachments
        score += len([a for a in analysis['attachments'] if a.get('is_suspicious')]) * 15

        # Suspicious indicators
        for indicator in analysis['suspicious_indicators']:
            if indicator['severity'] == 'CRITICAL':
                score += 20
            elif indicator['severity'] == 'HIGH':
                score += 15
            elif indicator['severity'] == 'MEDIUM':
                score += 10

        return min(score, 100)

    def trace_sender_geolocation(self, analysis: Dict) -> List[Dict]:
        """
        Trace sender through geolocation of mail server hops.

        Args:
            analysis: Email analysis dictionary

        Returns:
            List of geolocated hops
        """
        from ..geolocation.ip_intelligence import IPIntelligence

        intel = IPIntelligence()
        route = analysis.get('route_analysis', {})
        hops = route.get('hops', [])

        geolocated_hops = []

        for hop in hops:
            if hop.get('from_ip'):
                ip_analysis = intel.analyze_ip(hop['from_ip'])

                geolocated_hop = {
                    **hop,
                    'geolocation': ip_analysis.get('geolocation', {}),
                    'isp_info': ip_analysis.get('isp_info', {}),
                }

                geolocated_hops.append(geolocated_hop)

        return geolocated_hops

    def generate_report(self, output_path: str) -> None:
        """Generate email forensics report"""
        with open(output_path, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("EMAIL FORENSICS REPORT\n")
            f.write("=" * 100 + "\n\n")

            for analysis in self.analyzed_emails:
                basic = analysis['basic_info']
                sender = analysis['sender_info']
                route = analysis['route_analysis']

                f.write(f"Subject: {basic['subject']}\n")
                f.write(f"Date: {basic['date']}\n")
                f.write(f"Message-ID: {basic['message_id']}\n")
                f.write("-" * 100 + "\n\n")

                # Sender info
                f.write("SENDER INFORMATION:\n")
                f.write(f"  From: {sender['from_name']} <{sender['from_address']}>\n")
                f.write(f"  Domain: {sender['sender_domain']}\n")
                f.write(f"  Return-Path: {sender['return_path']}\n")

                if sender.get('spoofing_indicators'):
                    f.write(f"  ⚠️ Spoofing Indicators: {', '.join(sender['spoofing_indicators'])}\n")

                f.write("\n")

                # Email route
                f.write("EMAIL ROUTE:\n")
                f.write(f"  Total Hops: {route['total_hops']}\n")
                f.write(f"  Originating IP: {route['originating_ip']}\n")
                f.write(f"  First Server: {route['first_server']}\n\n")

                for hop in route['hops']:
                    f.write(f"  Hop {hop['hop_number']}: {hop['from_host']} [{hop['from_ip']}]\n")

                f.write("\n")

                # Authentication
                auth = analysis['authentication']
                f.write("AUTHENTICATION:\n")
                f.write(f"  SPF: {'PASS' if auth['spf']['pass'] else 'FAIL'}\n")
                f.write(f"  DKIM: {'PASS' if auth['dkim']['pass'] else 'FAIL'}\n")
                f.write(f"  DMARC: {'PASS' if auth['dmarc']['pass'] else 'FAIL'}\n")
                f.write(f"  Authenticated: {'Yes' if auth['is_authenticated'] else 'No'}\n\n")

                # Attachments
                if analysis['attachments']:
                    f.write("ATTACHMENTS:\n")
                    for att in analysis['attachments']:
                        suspicious = " [SUSPICIOUS]" if att['is_suspicious'] else ""
                        f.write(f"  - {att['filename']} ({att['size']} bytes){suspicious}\n")
                    f.write("\n")

                # Risk assessment
                f.write(f"RISK SCORE: {analysis['risk_score']}/100\n")

                if analysis['suspicious_indicators']:
                    f.write("\nSUSPICIOUS INDICATORS:\n")
                    for indicator in analysis['suspicious_indicators']:
                        f.write(f"  [{indicator['severity']}] {indicator['description']}\n")

                f.write("\n" + "=" * 100 + "\n\n")

        logger.info(f"Report saved to {output_path}")


def main():
    """Example usage of EmailIntelligence"""
    import argparse

    parser = argparse.ArgumentParser(description='Email Intelligence Tool')
    parser.add_argument('--email', required=True, help='Email file (.eml)')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--trace', action='store_true', help='Trace sender geolocation')

    args = parser.parse_args()

    intel = EmailIntelligence()

    print(f"\n📧 Analyzing email: {args.email}")
    analysis = intel.analyze_email_file(args.email)

    sender = analysis['sender_info']
    print(f"  From: {sender['from_address']}")
    print(f"  Risk Score: {analysis['risk_score']}/100")
    print(f"  Authentication: {'PASS' if analysis['authentication']['is_authenticated'] else 'FAIL'}")

    if args.trace:
        print(f"\n🌍 Tracing sender location...")
        geolocated_hops = intel.trace_sender_geolocation(analysis)
        for hop in geolocated_hops:
            geo = hop.get('geolocation', {})
            print(f"  Hop {hop['hop_number']}: {geo.get('city')}, {geo.get('country')}")

    intel.generate_report(args.output)
    print(f"\n✓ Report saved to: {args.output}")


if __name__ == '__main__':
    main()
