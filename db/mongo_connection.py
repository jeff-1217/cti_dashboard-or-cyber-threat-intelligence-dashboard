"""
MongoDB connection and database operations
"""
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class MongoDBConnection:
    """Handles MongoDB connections and operations"""
    
    def __init__(self):
        self.client = None
        self.db = None
        self.connect()
    
    def connect(self):
        """Establish connection to MongoDB"""
        try:
            self.client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[Config.MONGO_DB_NAME]
            print(f"Connected to MongoDB: {Config.MONGO_DB_NAME}")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"MongoDB connection error: {e}")
            self.client = None
            self.db = None
    
    def insert_threat(self, threat_data):
        """
        Insert a threat record into the database
        
        Args:
            threat_data (dict): Threat information including IP, domain, scores, etc.
        
        Returns:
            str: Inserted document ID
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return None
        
        # Add timestamp if not present
        if 'created_at' not in threat_data:
            threat_data['created_at'] = datetime.utcnow()
        
        # Add updated_at timestamp
        threat_data['updated_at'] = datetime.utcnow()
        
        try:
            result = self.db.threats.insert_one(threat_data)
            return str(result.inserted_id)
        except Exception as e:
            print(f"Error inserting threat: {e}")
            return None
    
    def find_threat(self, ip_or_domain):
        """
        Find existing threat record by IP or domain
        
        Args:
            ip_or_domain (str): IP address or domain to search for
        
        Returns:
            dict: Threat record or None
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return None
        
        try:
            return self.db.threats.find_one({
                '$or': [
                    {'ip': ip_or_domain},
                    {'domain': ip_or_domain}
                ]
            })
        except Exception as e:
            print(f"Error finding threat: {e}")
            return None
    
    def update_threat(self, ip_or_domain, update_data):
        """
        Update existing threat record
        
        Args:
            ip_or_domain (str): IP or domain to update
            update_data (dict): Data to update
        
        Returns:
            bool: True if successful
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return False
        
        update_data['updated_at'] = datetime.utcnow()
        
        try:
            result = self.db.threats.update_one(
                {
                    '$or': [
                        {'ip': ip_or_domain},
                        {'domain': ip_or_domain}
                    ]
                },
                {'$set': update_data}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating threat: {e}")
            return False
    
    def get_all_threats(self, limit=100, skip=0):
        """
        Get all threats with pagination
        
        Args:
            limit (int): Maximum number of records
            skip (int): Number of records to skip
        
        Returns:
            list: List of threat records
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return []
        
        try:
            cursor = self.db.threats.find().sort('created_at', -1).skip(skip).limit(limit)
            return list(cursor)
        except Exception as e:
            print(f"Error getting threats: {e}")
            return []
    
    def get_threat_count(self):
        """Get total count of threats"""
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return 0
        
        try:
            return self.db.threats.count_documents({})
        except Exception as e:
            print(f"Error counting threats: {e}")
            return 0
    
    def get_top_malicious_ips(self, limit=10):
        """
        Get top malicious IPs by threat score
        
        Args:
            limit (int): Number of IPs to return
        
        Returns:
            list: List of top malicious IPs
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return []
        
        try:
            pipeline = [
                {'$match': {'ip': {'$exists': True, '$ne': None}}},
                {'$sort': {'threat_score': -1}},
                {'$limit': limit},
                {'$project': {
                    'ip': 1,
                    'threat_score': 1,
                    'confidence': 1,
                    'country': 1,
                    'tags': 1,
                    'created_at': 1
                }}
            ]
            return list(self.db.threats.aggregate(pipeline))
        except Exception as e:
            print(f"Error getting top malicious IPs: {e}")
            return []
    
    def get_threats_by_category(self):
        """
        Get threat counts grouped by category/tag
        
        Returns:
            dict: Category counts
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return {}
        
        try:
            pipeline = [
                {'$unwind': '$tags'},
                {'$group': {
                    '_id': '$tags',
                    'count': {'$sum': 1}
                }},
                {'$sort': {'count': -1}}
            ]
            results = list(self.db.threats.aggregate(pipeline))
            return {item['_id']: item['count'] for item in results}
        except Exception as e:
            print(f"Error getting threats by category: {e}")
            return {}
    
    def get_threats_over_time(self, days=7):
        """
        Get threat counts grouped by date
        
        Args:
            days (int): Number of days to look back
        
        Returns:
            list: List of date-count pairs
        """
        if self.db is None:
            self.connect()
        
        if self.db is None:
            return []
        
        try:
            from datetime import timedelta
            start_date = datetime.utcnow() - timedelta(days=days)
            
            pipeline = [
                {'$match': {'created_at': {'$gte': start_date}}},
                {'$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}},
                    'count': {'$sum': 1}
                }},
                {'$sort': {'_id': 1}}
            ]
            results = list(self.db.threats.aggregate(pipeline))
            return [{'date': item['_id'], 'count': item['count']} for item in results]
        except Exception as e:
            print(f"Error getting threats over time: {e}")
            return []
    
    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()

# Global database instance
db_instance = MongoDBConnection()

