"""
AbuseIPDB API integration service
"""
import requests
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class AbuseIPDBService:
    """Service for interacting with AbuseIPDB API"""
    
    def __init__(self):
        self.base_url = Config.ABUSEIPDB_API_URL
    
    @property
    def api_key(self):
        """Get API key (always fresh from config)"""
        return Config.get_abuseipdb_key()
    
    def check_ip(self, ip_address, max_age_in_days=90):
        """
        Check IP address using AbuseIPDB
        
        Args:
            ip_address (str): IP address to check
            max_age_in_days (int): Maximum age of reports to consider
        
        Returns:
            dict: Abuse information including confidence score, categories, etc.
        """
        if not self.api_key:
            return {
                'error': 'AbuseIPDB API key not configured',
                'source': 'abuseipdb'
            }
        
        try:
            url = f"{self.base_url}/check"
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': max_age_in_days,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data:
                abuse_data = data['data']
                
                # AbuseIPDB API v2 uses 'abuseConfidenceScore' (0-100), not 'abuseConfidencePercentage'
                # Also check for 'abuseConfidencePercentage' for backward compatibility
                abuse_confidence = abuse_data.get('abuseConfidenceScore', 
                                                  abuse_data.get('abuseConfidencePercentage', 0))
                
                is_public = abuse_data.get('isPublic', False)
                usage_type = abuse_data.get('usageType', 'Unknown')
                isp = abuse_data.get('isp', 'Unknown')
                country = abuse_data.get('countryCode', 'Unknown')
                country_name = abuse_data.get('countryName', country)
                domain = abuse_data.get('domain', 'Unknown')
                
                # Get number of reports
                # numReports: Reports within maxAgeInDays window
                # totalReports: All-time reports (if available)
                num_reports = abuse_data.get('numReports', 0)
                total_reports = abuse_data.get('totalReports', num_reports)  # Fallback to numReports if totalReports not available
                
                # Extract categories from usageType
                usage_type_str = usage_type
                category_names = self._map_categories(usage_type)
                
                # Also check for abuse categories if available
                if 'reports' in abuse_data and isinstance(abuse_data['reports'], list):
                    # Extract unique categories from reports
                    report_categories = set()
                    for report in abuse_data['reports']:
                        cats = report.get('categories', [])
                        if isinstance(cats, list):
                            report_categories.update(cats)
                    if report_categories:
                        # Map category codes to names
                        category_names.extend(self._map_abuse_categories(list(report_categories)))
                        category_names = list(set(category_names))  # Remove duplicates
                
                # Calculate threat score based on confidence
                # If confidence is high (>= 75), threat score should reflect that
                threat_score = abuse_confidence
                
                return {
                    'source': 'abuseipdb',
                    'ip': ip_address,
                    'threat_score': threat_score,
                    'confidence': abuse_confidence,
                    'is_public': is_public,
                    'usage_type': usage_type,
                    'isp': isp,
                    'country': country,
                    'country_name': country_name,
                    'domain': domain,
                    'is_whitelisted': abuse_data.get('isWhitelisted', False),
                    'abuse_confidence': abuse_confidence,
                    'abuse_confidence_score': abuse_confidence,  # Alias for clarity
                    'num_reports': num_reports,  # Reports in last maxAgeInDays
                    'total_reports': total_reports,  # All-time reports
                    'last_reported_at': abuse_data.get('lastReportedAt'),
                    'tags': category_names,
                    'raw_response': abuse_data
                }
            else:
                return {
                    'error': data.get('errors', [{}])[0].get('detail', 'Unknown error'),
                    'source': 'abuseipdb'
                }
        
        except requests.exceptions.RequestException as e:
            return {
                'error': f'API request failed: {str(e)}',
                'source': 'abuseipdb'
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'source': 'abuseipdb'
            }
    
    def _map_categories(self, categories):
        """
        Map AbuseIPDB usage type to readable names
        
        Args:
            categories: Usage type string
        
        Returns:
            list: List of category names
        """
        if isinstance(categories, str):
            # Usage type is a string like "Data Center/Web Hosting/Transit"
            return [categories] if categories and categories != 'Unknown' else []
        elif isinstance(categories, list):
            return [str(c) for c in categories if c]
        else:
            return []
    
    def _map_abuse_categories(self, category_codes):
        """
        Map AbuseIPDB abuse category codes to readable names
        
        Args:
            category_codes: List of category code numbers
        
        Returns:
            list: List of category names
        """
        # AbuseIPDB category codes mapping
        category_map = {
            3: 'Fraud Orders',
            4: 'DDoS Attack',
            5: 'FTP Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open Proxy',
            10: 'Web Spam',
            11: 'Email Spam',
            12: 'Blog Spam',
            13: 'VPN IP',
            14: 'Port Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute-Force',
            19: 'Bad Web Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH',
            23: 'IoT Targeted',
            24: 'Malware'
        }
        
        category_names = []
        for code in category_codes:
            if isinstance(code, int) and code in category_map:
                category_names.append(category_map[code])
            elif isinstance(code, str):
                try:
                    code_int = int(code)
                    if code_int in category_map:
                        category_names.append(category_map[code_int])
                except ValueError:
                    pass
        
        return category_names

