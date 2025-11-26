"""
VirusTotal API integration service
"""
import requests
import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class VirusTotalService:
    """Service for interacting with VirusTotal API"""
    
    def __init__(self):
        self.base_url = Config.VIRUSTOTAL_API_URL
    
    @property
    def api_key(self):
        """Get API key (always fresh from config)"""
        return Config.get_virustotal_key()
    
    def check_ip(self, ip_address):
        """
        Check IP address reputation using VirusTotal
        
        Args:
            ip_address (str): IP address to check
        
        Returns:
            dict: Threat information including score, detections, etc.
        """
        if not self.api_key:
            return {
                'error': 'VirusTotal API key not configured',
                'source': 'virustotal'
            }
        
        try:
            url = f"{self.base_url}/ip-address/report"
            params = {
                'apikey': self.api_key,
                'ip': ip_address
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('response_code') == 1:
                # IP found in database
                detections = data.get('detected_urls', [])
                detection_count = len(detections) if isinstance(detections, list) else 0
                # detected_communicating_samples can be a list or int
                communicating_samples = data.get('detected_communicating_samples', 0)
                if isinstance(communicating_samples, list):
                    total_scans = len(communicating_samples)
                else:
                    total_scans = int(communicating_samples) if communicating_samples else 0
                
                # Calculate threat score (0-100)
                # Each detection is significant, so weight them higher
                # Base score from detections: 15 points per detection (max 60)
                # Additional score from samples: 10 points per sample (max 40)
                detection_score = min(60, detection_count * 15)
                sample_score = min(40, total_scans * 10)
                threat_score = min(100, detection_score + sample_score)
                
                # If there are any detections, minimum score should be 25
                if detection_count > 0 and threat_score < 25:
                    threat_score = 25
                
                return {
                    'source': 'virustotal',
                    'ip': ip_address,
                    'threat_score': threat_score,
                    'detection_count': detection_count,
                    'total_scans': total_scans,
                    'country': data.get('country', 'Unknown'),
                    'asn': data.get('asn', 'Unknown'),
                    'detected_urls': detections[:5],  # Top 5 detections
                    'last_seen': data.get('as_owner', 'Unknown'),
                    'tags': self._extract_tags(data),
                    'raw_response': data
                }
            elif data.get('response_code') == 0:
                # IP not found in database
                return {
                    'source': 'virustotal',
                    'ip': ip_address,
                    'threat_score': 0,
                    'detection_count': 0,
                    'message': 'IP not found in VirusTotal database',
                    'tags': []
                }
            else:
                return {
                    'error': data.get('verbose_msg', 'Unknown error'),
                    'source': 'virustotal'
                }
        
        except requests.exceptions.RequestException as e:
            return {
                'error': f'API request failed: {str(e)}',
                'source': 'virustotal'
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'source': 'virustotal'
            }
    
    def check_domain(self, domain):
        """
        Check domain reputation using VirusTotal
        
        Args:
            domain (str): Domain to check
        
        Returns:
            dict: Threat information
        """
        if not self.api_key:
            return {
                'error': 'VirusTotal API key not configured',
                'source': 'virustotal'
            }
        
        try:
            url = f"{self.base_url}/domain/report"
            params = {
                'apikey': self.api_key,
                'domain': domain
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('response_code') == 1:
                detected_urls = data.get('detected_urls', [])
                detection_count = len(detected_urls)
                detected_samples = data.get('detected_samples', [])
                sample_count = len(detected_samples)
                
                # Calculate threat score
                threat_score = min(100, (detection_count * 10) + (sample_count * 5))
                
                return {
                    'source': 'virustotal',
                    'domain': domain,
                    'threat_score': threat_score,
                    'detection_count': detection_count,
                    'sample_count': sample_count,
                    'subdomains': data.get('subdomains', [])[:10],  # Top 10
                    'resolutions': data.get('resolutions', [])[:10],  # Top 10
                    'tags': self._extract_tags(data),
                    'raw_response': data
                }
            elif data.get('response_code') == 0:
                return {
                    'source': 'virustotal',
                    'domain': domain,
                    'threat_score': 0,
                    'detection_count': 0,
                    'message': 'Domain not found in VirusTotal database',
                    'tags': []
                }
            else:
                return {
                    'error': data.get('verbose_msg', 'Unknown error'),
                    'source': 'virustotal'
                }
        
        except requests.exceptions.RequestException as e:
            return {
                'error': f'API request failed: {str(e)}',
                'source': 'virustotal'
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'source': 'virustotal'
            }
    
    def _extract_tags(self, data):
        """Extract threat tags from VirusTotal response"""
        tags = []
        
        # Check for common threat indicators
        if data.get('detected_urls'):
            tags.append('malware')
        if data.get('detected_samples'):
            tags.append('malware')
        if data.get('detected_communicating_samples'):
            tags.append('command-and-control')
        
        # Add category if available
        category = data.get('category', '')
        if category:
            tags.append(category.lower())
        
        return list(set(tags)) if tags else ['unknown']

