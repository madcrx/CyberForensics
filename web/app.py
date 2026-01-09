"""
CyberForensics Web Portal
Professional web interface for the forensics toolkit.
"""

from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from werkzeug.utils import secure_filename
import sys
import os
from pathlib import Path
import json
import subprocess
from datetime import datetime
import tempfile

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyberforensics-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = '/app/data/uploads'
app.config['REPORTS_FOLDER'] = '/app/reports'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Ensure directories exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
Path(app.config['REPORTS_FOLDER']).mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap', 'exe', 'dll', 'pdf', 'eml', 'msg', 'txt',
                     'img', 'dd', 'raw', 'jpg', 'png', 'gif', 'zip', 'rar', 'hash'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ==================== PAGE ROUTES ====================

@app.route('/')
def index():
    """Main dashboard"""
    stats = {
        'total_tools': 8,
        'tools_available': 8,
        'reports_generated': len(list(Path(app.config['REPORTS_FOLDER']).glob('*'))),
    }
    return render_template('index.html', stats=stats)


@app.route('/file-forensics')
def file_forensics():
    """File forensics interface"""
    return render_template('file_forensics.html')


@app.route('/network-analysis')
def network_analysis():
    """Network analysis interface"""
    return render_template('network_analysis.html')


@app.route('/malware-analysis')
def malware_analysis():
    """Malware analysis interface"""
    return render_template('malware_analysis.html')


@app.route('/password-recovery')
def password_recovery():
    """Password recovery interface"""
    return render_template('password_recovery.html')


@app.route('/osint')
def osint():
    """OSINT interface"""
    return render_template('osint.html')


@app.route('/geolocation')
def geolocation():
    """Geolocation interface"""
    return render_template('geolocation.html')


@app.route('/email-forensics')
def email_forensics():
    """Email forensics interface"""
    return render_template('email_forensics.html')


@app.route('/attribution')
def attribution():
    """Attribution engine interface"""
    return render_template('attribution.html')


@app.route('/reports')
def reports():
    """View generated reports"""
    reports_dir = Path(app.config['REPORTS_FOLDER'])
    reports_list = []

    for report_file in reports_dir.glob('*'):
        if report_file.is_file():
            reports_list.append({
                'name': report_file.name,
                'size': report_file.stat().st_size,
                'modified': datetime.fromtimestamp(report_file.stat().st_mtime).isoformat(),
                'type': report_file.suffix
            })

    return render_template('reports.html', reports=reports_list)


@app.route('/reports/<filename>')
def download_report(filename):
    """Download a specific report"""
    return send_from_directory(app.config['REPORTS_FOLDER'], filename)


# ==================== API ROUTES ====================

@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'tools_available': 8,
        'timestamp': datetime.now().isoformat()
    })


# ==================== GEOLOCATION APIs ====================

@app.route('/api/analyze-ip', methods=['POST'])
def api_analyze_ip():
    """API endpoint for IP analysis"""
    try:
        data = request.get_json()
        ip_address = data.get('ip')

        if not ip_address:
            return jsonify({'error': 'IP address required'}), 400

        from tools.geolocation.ip_intelligence import IPIntelligence

        intel = IPIntelligence()
        result = intel.analyze_ip(ip_address)

        return jsonify(result)

    except Exception as e:
        app.logger.error(f"IP analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    """API endpoint for traceroute"""
    try:
        data = request.get_json()
        destination = data.get('destination')

        if not destination:
            return jsonify({'error': 'Destination required'}), 400

        from tools.geolocation.traceroute_analyzer import TracerouteAnalyzer

        analyzer = TracerouteAnalyzer()
        hops = analyzer.trace_route(destination)

        return jsonify({'hops': hops, 'total_hops': len(hops)})

    except Exception as e:
        app.logger.error(f"Traceroute error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== PASSWORD RECOVERY APIs ====================

@app.route('/api/hash-crack', methods=['POST'])
def api_hash_crack():
    """API endpoint for hash cracking"""
    try:
        data = request.get_json()
        hash_value = data.get('hash')
        algorithm = data.get('algorithm', 'md5')
        method = data.get('method', 'smart')

        if not hash_value:
            return jsonify({'error': 'Hash value required'}), 400

        from tools.password_recovery.hash_cracker import HashCracker

        cracker = HashCracker()

        # Use dictionary attack with wordlist
        wordlist_path = Path('/app/data/wordlists/common_passwords.txt')

        password = None
        if method == 'smart':
            context = {'username': data.get('username', '')}
            password = cracker.crack_hash_smart(hash_value, algorithm, context)
        elif method == 'dictionary' and wordlist_path.exists():
            password = cracker.crack_hash_dictionary(hash_value, algorithm, str(wordlist_path))
        else:
            # Try smart attack as fallback
            password = cracker.crack_hash_smart(hash_value, algorithm, {})

        if password:
            analysis = cracker.analyze_password_strength(password)
            return jsonify({
                'success': True,
                'password': password,
                'algorithm': algorithm,
                'strength': analysis.get('strength', 'Unknown'),
                'entropy': analysis.get('entropy_bits', 0),
                'recommendations': analysis.get('recommendations', [])
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to crack hash. Try a different wordlist or attack method.'
            })

    except Exception as e:
        app.logger.error(f"Hash cracking error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== MALWARE ANALYSIS APIs ====================

@app.route('/api/analyze-malware', methods=['POST'])
def api_analyze_malware():
    """API endpoint for malware analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if file:
            filename = secure_filename(file.filename)
            filepath = Path(app.config['UPLOAD_FOLDER']) / filename
            file.save(str(filepath))

            from tools.malware_analysis.static_analyzer import StaticMalwareAnalyzer
            from tools.malware_analysis.signature_detector import SignatureDetector

            analyzer = StaticMalwareAnalyzer()
            detector = SignatureDetector()

            # Perform static analysis
            analysis = analyzer.analyze_file(str(filepath))

            # Check signatures
            signatures = detector.scan_file(str(filepath))
            analysis['signature_matches'] = signatures

            # Clean up uploaded file
            filepath.unlink()

            return jsonify(analysis)

    except Exception as e:
        app.logger.error(f"Malware analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hash-lookup', methods=['POST'])
def api_hash_lookup():
    """API endpoint for hash lookup"""
    try:
        data = request.get_json()
        file_hash = data.get('hash')

        if not file_hash:
            return jsonify({'error': 'Hash required'}), 400

        # Simulate hash lookup (in production, query VirusTotal, etc.)
        result = {
            'hash': file_hash,
            'found': True,
            'malware_detected': True,
            'detection_name': 'Trojan.Generic.KeyLogger',
            'threat_level': 'High',
            'first_seen': '2025-11-15',
            'last_seen': '2026-01-09'
        }

        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Hash lookup error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== NETWORK ANALYSIS APIs ====================

@app.route('/api/analyze-pcap', methods=['POST'])
def api_analyze_pcap():
    """API endpoint for PCAP analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = Path(app.config['UPLOAD_FOLDER']) / filename
            file.save(str(filepath))

            from tools.network_analysis.packet_analyzer import PacketAnalyzer

            analyzer = PacketAnalyzer()
            report_path = Path(app.config['REPORTS_FOLDER']) / f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

            # Analyze PCAP
            result = analyzer.analyze_pcap(str(filepath), str(report_path))

            # Clean up uploaded file
            filepath.unlink()

            return jsonify({
                'success': True,
                'report': result,
                'report_file': report_path.name
            })

    except Exception as e:
        app.logger.error(f"PCAP analysis error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== EMAIL FORENSICS APIs ====================

@app.route('/api/analyze-email', methods=['POST'])
def api_analyze_email():
    """API endpoint for email analysis"""
    try:
        headers = None

        # Check if file was uploaded
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                filename = secure_filename(file.filename)
                filepath = Path(app.config['UPLOAD_FOLDER']) / filename
                file.save(str(filepath))

                # Read file content
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    headers = f.read()

                filepath.unlink()
        else:
            # Get headers from form data
            data = request.get_json()
            headers = data.get('headers')

        if not headers:
            return jsonify({'error': 'Email headers required'}), 400

        from tools.email_forensics.email_intelligence import EmailIntelligence

        analyzer = EmailIntelligence()
        result = analyzer.analyze_email(headers)

        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Email analysis error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== OSINT APIs ====================

@app.route('/api/osint-search', methods=['POST'])
def api_osint_search():
    """API endpoint for OSINT profile search"""
    try:
        data = request.get_json()
        username = data.get('username')
        platforms = data.get('platforms', [])

        if not username:
            return jsonify({'error': 'Username required'}), 400

        from tools.social_media_osint.profile_analyzer import ProfileAnalyzer

        analyzer = ProfileAnalyzer()

        # Search across platforms
        profiles = []
        for platform in platforms:
            profile = analyzer.analyze_profile(username, platform)
            if profile:
                profiles.append(profile)

        # Calculate correlation
        correlation = analyzer.correlate_profiles(profiles) if len(profiles) > 1 else {}

        return jsonify({
            'username': username,
            'profiles_found': len(profiles),
            'profiles': profiles,
            'correlation': correlation,
            'platforms_searched': platforms
        })

    except Exception as e:
        app.logger.error(f"OSINT search error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== FILE FORENSICS APIs ====================

@app.route('/api/recover-files', methods=['POST'])
def api_recover_files():
    """API endpoint for file recovery"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if file:
            filename = secure_filename(file.filename)
            filepath = Path(app.config['UPLOAD_FOLDER']) / filename
            file.save(str(filepath))

            from tools.file_forensics.file_recovery import FileRecoveryTool

            recovery = FileRecoveryTool()
            output_dir = Path(app.config['REPORTS_FOLDER']) / f"recovered_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            output_dir.mkdir(exist_ok=True)

            # Perform file recovery
            recovered = recovery.recover_from_image(str(filepath), str(output_dir))

            # Clean up uploaded file
            filepath.unlink()

            return jsonify({
                'success': True,
                'files_recovered': len(recovered),
                'files': recovered[:50],  # Limit to first 50
                'output_directory': str(output_dir)
            })

    except Exception as e:
        app.logger.error(f"File recovery error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze-metadata', methods=['POST'])
def api_analyze_metadata():
    """API endpoint for metadata analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if file:
            filename = secure_filename(file.filename)
            filepath = Path(app.config['UPLOAD_FOLDER']) / filename
            file.save(str(filepath))

            from tools.file_forensics.metadata_analyzer import MetadataAnalyzer

            analyzer = MetadataAnalyzer()
            metadata = analyzer.extract_metadata(str(filepath))

            # Clean up uploaded file
            filepath.unlink()

            return jsonify(metadata)

    except Exception as e:
        app.logger.error(f"Metadata analysis error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ATTRIBUTION APIs ====================

@app.route('/api/correlate-evidence', methods=['POST'])
def api_correlate_evidence():
    """API endpoint for evidence correlation"""
    try:
        data = request.get_json()
        evidence_sources = data.get('sources', [])

        if not evidence_sources:
            return jsonify({'error': 'No evidence sources provided'}), 400

        from tools.user_attribution.attribution_engine import AttributionEngine

        engine = AttributionEngine()

        # Add evidence from each source
        for source in evidence_sources:
            engine.add_evidence(
                source_type=source.get('type'),
                data=source.get('data'),
                timestamp=source.get('timestamp', datetime.now().isoformat())
            )

        # Correlate indicators
        suspects = engine.correlate_indicators()
        timeline = engine.generate_timeline()

        return jsonify({
            'suspects': suspects,
            'timeline': timeline,
            'evidence_sources': len(evidence_sources),
            'indicators_found': len(engine.indicators)
        })

    except Exception as e:
        app.logger.error(f"Evidence correlation error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 500MB'}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
