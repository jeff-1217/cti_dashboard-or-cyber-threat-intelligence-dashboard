"""
Main Flask application for CTI Dashboard
"""
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from datetime import datetime
from bson import ObjectId
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from db.mongo_connection import db_instance
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from utils.scheduler import scheduler_instance
from utils.exporter import ThreatExporter

app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)

# Helper function to convert MongoDB documents to JSON-serializable format
def serialize_document(doc):
    """Convert MongoDB document to JSON-serializable dict"""
    if doc is None:
        return None
    result = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        else:
            result[key] = value
    return result

# Initialize services
vt_service = VirusTotalService()
abuse_service = AbuseIPDBService()
exporter = ThreatExporter()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/lookup')
def lookup():
    """IP/Domain lookup page"""
    return render_template('lookup.html')

@app.route('/export')
def export_page():
    """Export page"""
    return render_template('export.html')

@app.route('/api/lookup', methods=['POST'])
def api_lookup():
    """
    API endpoint for IP/domain lookup
    """
    data = request.get_json()
    ip_or_domain = data.get('query', '').strip()
    
    if not ip_or_domain:
        return jsonify({'error': 'IP or domain required'}), 400
    
    # Determine if it's an IP or domain
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = bool(re.match(ip_pattern, ip_or_domain))
    
    results = {
        'query': ip_or_domain,
        'type': 'ip' if is_ip else 'domain',
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Check existing record
    existing = db_instance.find_threat(ip_or_domain)
    
    # Fetch from APIs
    if is_ip:
        vt_result = vt_service.check_ip(ip_or_domain)
        abuse_result = abuse_service.check_ip(ip_or_domain)
    else:
        vt_result = vt_service.check_domain(ip_or_domain)
        abuse_result = abuse_service.check_ip(ip_or_domain) if abuse_service.api_key else {'error': 'AbuseIPDB API key not configured'}
    
    # Combine results - handle cases where APIs return errors
    vt_score = vt_result.get('threat_score', 0) if not vt_result.get('error') else 0
    abuse_score = abuse_result.get('threat_score', 0) if not abuse_result.get('error') else 0
    
    threat_score = max(vt_score, abuse_score)
    
    vt_confidence = vt_result.get('detection_count', 0) if not vt_result.get('error') else 0
    abuse_confidence = abuse_result.get('confidence', 0) if not abuse_result.get('error') else 0
    confidence = max(vt_confidence, abuse_confidence)
    
    country = 'Unknown'
    if not vt_result.get('error') and vt_result.get('country'):
        country = vt_result.get('country')
    elif not abuse_result.get('error') and abuse_result.get('country'):
        country = abuse_result.get('country')
    
    tags = []
    if not vt_result.get('error') and vt_result.get('tags'):
        tags.extend(vt_result.get('tags', []))
    if not abuse_result.get('error') and abuse_result.get('tags'):
        tags.extend(abuse_result.get('tags', []))
    tags = list(set(tags)) if tags else []
    
    # Prepare threat data
    threat_data = {
        'ip' if is_ip else 'domain': ip_or_domain,
        'type': 'ip' if is_ip else 'domain',
        'vt_result': vt_result,
        'abuse_result': abuse_result,
        'threat_score': threat_score,
        'confidence': confidence,
        'country': country,
        'tags': tags
    }
    
    # Store or update in database
    if existing:
        db_instance.update_threat(ip_or_domain, threat_data)
    else:
        db_instance.insert_threat(threat_data)
    
    # Determine status - consider threat score, detections, and tags
    # Check for malware or malicious tags
    has_malware_tag = any(tag.lower() in ['malware', 'malicious', 'trojan', 'virus', 'ransomware', 'phishing'] 
                          for tag in tags)
    
    # Check for detections
    has_detections = vt_confidence > 0 or abuse_confidence > 0
    
    # Calculate status
    if threat_score >= 70 or (has_malware_tag and threat_score >= 30):
        status = 'malicious'
    elif threat_score >= 20 or has_malware_tag or (has_detections and threat_score >= 10):
        status = 'suspicious'
    elif threat_score > 0 or has_detections:
        status = 'suspicious'  # Even low scores with detections should be suspicious
    else:
        status = 'clean'
    
    # Prepare response
    results.update({
        'threat_score': threat_score,
        'confidence': confidence,
        'country': country,
        'tags': tags,
        'virustotal': vt_result,
        'abuseipdb': abuse_result,
        'status': status
    })
    
    return jsonify(results)

@app.route('/api/dashboard/stats')
def api_dashboard_stats():
    """Get dashboard statistics"""
    try:
        total_threats = db_instance.get_threat_count()
        top_ips = db_instance.get_top_malicious_ips(10)
        category_counts = db_instance.get_threats_by_category()
        threats_over_time = db_instance.get_threats_over_time(7)
        
        # Process top IPs for JSON serialization
        top_ips_processed = []
        for ip in top_ips:
            ip_dict = {
                'ip': ip.get('ip', ''),
                'threat_score': ip.get('threat_score', 0),
                'confidence': ip.get('confidence', 0),
                'country': ip.get('country', 'Unknown'),
                'tags': ip.get('tags', [])
            }
            top_ips_processed.append(ip_dict)
        
        return jsonify({
            'total_threats': total_threats,
            'top_malicious_ips': top_ips_processed,
            'category_counts': category_counts,
            'threats_over_time': threats_over_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/feeds')
def api_feeds():
    """
    JSON threat feed endpoint
    Returns all threats in JSON format
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        skip = request.args.get('skip', 0, type=int)
        
        threats = db_instance.get_all_threats(limit=limit, skip=skip)
        
        # Convert MongoDB documents to JSON-serializable format
        threats_list = [serialize_document(threat) for threat in threats]
        
        return jsonify({
            'count': len(threats_list),
            'total': db_instance.get_threat_count(),
            'threats': threats_list
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tag', methods=['POST'])
def api_tag():
    """
    Manually tag an IOC
    """
    data = request.get_json()
    ip_or_domain = data.get('query', '').strip()
    tag = data.get('tag', '').strip()
    
    if not ip_or_domain or not tag:
        return jsonify({'error': 'Query and tag required'}), 400
    
    existing = db_instance.find_threat(ip_or_domain)
    if not existing:
        return jsonify({'error': 'Threat not found'}), 404
    
    # Add tag if not already present
    current_tags = existing.get('tags', [])
    if tag not in current_tags:
        current_tags.append(tag)
    
    db_instance.update_threat(ip_or_domain, {'tags': current_tags})
    
    return jsonify({'success': True, 'tags': current_tags})

@app.route('/api/export/csv', methods=['POST'])
def api_export_csv():
    """Export threats to CSV"""
    try:
        data = request.get_json() or {}
        limit = data.get('limit', 1000)
        
        threats = db_instance.get_all_threats(limit=limit)
        filepath = exporter.export_to_csv(threats)
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(filepath),
            mimetype='text/csv'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/pdf', methods=['POST'])
def api_export_pdf():
    """Export threats to PDF"""
    try:
        data = request.get_json() or {}
        limit = data.get('limit', 1000)
        
        threats = db_instance.get_all_threats(limit=limit)
        filepath = exporter.export_to_pdf(threats)
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(filepath),
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Start scheduler
    scheduler_instance.start()
    
    try:
        # Run Flask app
        # Using port 5001 to avoid conflict with macOS AirPlay Receiver (port 5000)
        port = int(os.environ.get('PORT', 5001))
        app.run(debug=True, host='0.0.0.0', port=port)
    except KeyboardInterrupt:
        scheduler_instance.stop()

