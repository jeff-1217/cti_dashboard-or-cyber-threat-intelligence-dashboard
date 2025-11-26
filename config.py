"""
Configuration file for CTI Dashboard
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv(override=True)

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # MongoDB Configuration
    MONGO_URI = os.environ.get('MONGO_URI') or 'mongodb://localhost:27017/'
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME') or 'cti_dashboard'
    
    # API Endpoints
    VIRUSTOTAL_API_URL = 'https://www.virustotal.com/vtapi/v2'
    ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2'
    
    # Scheduler Configuration
    SCHEDULER_INTERVAL_MINUTES = 30
    
    # Export Configuration
    EXPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exports')
    
    # API Keys - reload from env each time
    @classmethod
    def get_virustotal_key(cls):
        """Get VirusTotal API key (always fresh from env)"""
        load_dotenv(override=True)
        return os.environ.get('VT_API_KEY') or ''
    
    @classmethod
    def get_abuseipdb_key(cls):
        """Get AbuseIPDB API key (always fresh from env)"""
        load_dotenv(override=True)
        return os.environ.get('ABUSEIPDB_KEY') or ''
    
    # Static access (reloads each call)
    @staticmethod
    def reload_env():
        """Reload environment variables from .env file"""
        load_dotenv(override=True)
    
    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        # Create export directory if it doesn't exist
        os.makedirs(Config.EXPORT_DIR, exist_ok=True)

# Convenience functions to get API keys (always fresh)
def get_virustotal_key():
    """Get VirusTotal API key from environment"""
    load_dotenv(override=True)
    return os.environ.get('VT_API_KEY') or ''

def get_abuseipdb_key():
    """Get AbuseIPDB API key from environment"""
    load_dotenv(override=True)
    return os.environ.get('ABUSEIPDB_KEY') or ''
