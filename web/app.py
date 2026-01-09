"""
CyberForensics Web Portal
Professional web interface for the forensics toolkit.
"""

from flask import Flask, render_template, request, jsonify, send_file
import sys
import os
from pathlib import Path
import json
import subprocess
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyberforensics-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = '/data/uploads'
app.config['REPORTS_FOLDER'] = '/data/reports'

# Ensure directories exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
Path(app.config['REPORTS_FOLDER']).mkdir(parents=True, exist_ok=True)


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

        return jsonify({'hops': hops})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


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

        password = None
        if method == 'smart':
            context = {'username': data.get('username', '')}
            password = cracker.crack_hash_smart(hash_value, algorithm, context)

        if password:
            analysis = cracker.analyze_password_strength(password)
            return jsonify({
                'success': True,
                'password': password,
                'strength': analysis['strength'],
                'entropy': analysis['entropy_bits']
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to crack hash'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'tools_available': 8,
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
