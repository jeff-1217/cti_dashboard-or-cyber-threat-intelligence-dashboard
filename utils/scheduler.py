"""
APScheduler configuration for automated threat data fetching
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config
from services.virustotal import VirusTotalService
from services.abuseipdb import AbuseIPDBService
from db.mongo_connection import db_instance
import random

class ThreatDataScheduler:
    """Manages scheduled tasks for fetching threat intelligence"""
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.vt_service = VirusTotalService()
        self.abuse_service = AbuseIPDBService()
    
    def fetch_sample_threats(self):
        """
        Fetch sample threat data from APIs
        This is a placeholder function - in production, you'd fetch from threat feeds
        """
        print("Fetching threat data...")
        
        # Sample malicious IPs for testing (in production, these would come from feeds)
        sample_ips = [
            '8.8.8.8',  # Google DNS (safe, for testing)
            '1.1.1.1',  # Cloudflare DNS (safe, for testing)
            # Add more test IPs or integrate with threat feeds
        ]
        
        for ip in sample_ips:
            try:
                # Check if already exists
                existing = db_instance.find_threat(ip)
                if existing:
                    continue
                
                # Fetch from APIs
                vt_result = self.vt_service.check_ip(ip)
                abuse_result = self.abuse_service.check_ip(ip)
                
                # Combine results
                threat_data = {
                    'ip': ip,
                    'type': 'ip',
                    'vt_result': vt_result,
                    'abuse_result': abuse_result,
                    'threat_score': max(
                        vt_result.get('threat_score', 0),
                        abuse_result.get('threat_score', 0)
                    ),
                    'confidence': max(
                        vt_result.get('detection_count', 0),
                        abuse_result.get('confidence', 0)
                    ),
                    'country': vt_result.get('country') or abuse_result.get('country', 'Unknown'),
                    'tags': list(set(
                        vt_result.get('tags', []) + abuse_result.get('tags', [])
                    ))
                }
                
                # Store in database
                db_instance.insert_threat(threat_data)
                print(f"Stored threat data for {ip}")
                
            except Exception as e:
                print(f"Error fetching threat data for {ip}: {e}")
    
    def start(self):
        """Start the scheduler"""
        # Add job to fetch threat data every 30 minutes
        self.scheduler.add_job(
            func=self.fetch_sample_threats,
            trigger=IntervalTrigger(minutes=Config.SCHEDULER_INTERVAL_MINUTES),
            id='fetch_threats',
            name='Fetch threat intelligence data',
            replace_existing=True
        )
        
        self.scheduler.start()
        print("Scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        self.scheduler.shutdown()
        print("Scheduler stopped")

# Global scheduler instance
scheduler_instance = ThreatDataScheduler()

