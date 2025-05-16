import pandas as pd
import json
import re
import ipaddress
import requests
from datetime import datetime

class EnhancedLogIngestor:
    """Enhanced ETL pipeline supporting multiple log formats and basic enrichment"""
    
    def __init__(self, config):
        self.config = config
        # Cache for IP enrichment data to avoid repeated lookups
        self.ip_cache = {}
        
    def load_logs(self, source):
        """Universal log loader supporting multiple formats"""
        print(f"[+] Loading logs from {source['path']} (format: {source['format']})")
        
        if source['format'] == 'csv':
            return self._load_csv(source['path'])
        elif source['format'] == 'json':
            return self._load_json(source['path'])
        elif source['format'] == 'syslog':
            return self._load_syslog(source['path'])
        else:
            print(f"[!] Unsupported format: {source['format']}")
            return []
    
    def _load_csv(self, path):
        """Load and parse CSV file"""
        return pd.read_csv(path).to_dict(orient='records')
    
    def _load_json(self, path):
        """Load and parse JSON file"""
        with open(path, 'r') as f:
            return json.load(f)
    
    def _load_syslog(self, path):
        """Load and parse syslog-format file"""
        events = []
        syslog_pattern = re.compile(
            r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)'
        )
        
        with open(path, 'r') as f:
            for line in f:
                match = syslog_pattern.match(line.strip())
                if match:
                    timestamp, host, service, pid, message = match.groups()
                    events.append({
                        'timestamp': timestamp,
                        'host': host,
                        'service': service,
                        'pid': pid,
                        'message': message
                    })
        return events
    
    def enrich_events(self, events):
        """Add enrichment data to events"""
        enriched = []
        
        for event in events:
            # Make a copy to avoid modifying the original
            enriched_event = event.copy()
            
            # Normalize timestamp if present but in different formats
            if 'timestamp' in enriched_event:
                enriched_event['@timestamp'] = self._normalize_timestamp(enriched_event['timestamp'])
            
            # Add source IP enrichment if available
            source_ip = enriched_event.get('source_ip')
            if source_ip and self._is_valid_ip(source_ip):
                geo_data = self._get_ip_geo(source_ip)
                if geo_data:
                    enriched_event['geo'] = geo_data
                    
            # Add simple risk score based on available indicators
            enriched_event['risk_score'] = self._calculate_risk_score(enriched_event)
            
            enriched.append(enriched_event)
            
        return enriched
    
    def _normalize_timestamp(self, timestamp):
        """Convert various timestamp formats to ISO standard"""
        # This is a simplified example - production would handle many formats
        try:
            if isinstance(timestamp, str):
                # Try a few common formats
                formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%b %d %H:%M:%S',
                    '%d/%b/%Y:%H:%M:%S'
                ]
                
                for fmt in formats:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        return dt.isoformat()
                    except ValueError:
                        continue
            
            return timestamp  # Return original if conversion failed
        except Exception:
            return timestamp
    
    def _is_valid_ip(self, ip):
        """Check if string is valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _get_ip_geo(self, ip):
        """Get geolocation data for IP (with caching)"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        # This would normally use a real geo-IP service
        # For demo, just return mock data
        mock_geo = {
            "country_code": "US",
            "country_name": "United States",
            "city": "Phoenix",
            "latitude": 33.4484,
            "longitude": -112.0740
        }
        
        self.ip_cache[ip] = mock_geo
        return mock_geo
    
    def _calculate_risk_score(self, event):
        """Calculate simple risk score based on event attributes"""
        score = 0
        
        # Use all available indicators
        if event.get('failed_logins', 0) >= 5:
            score += 20
            
        if event.get('unusual_time_access', 0) == 1:
            score += 30
            
        if event.get('attack_detected', 0) == 1:
            score += 25
            
        # Additional indicators
        if 'message' in event:
            message = event['message'].lower()
            if 'root' in message or 'admin' in message:
                score += 10
                
            if 'firewall' in message and 'block' in message:
                score += 15
                
        # IP reputation if available
        ip_reputation = event.get('ip_reputation_score', 0)
        if isinstance(ip_reputation, (int, float)) and ip_reputation > 0.5:
            score += 15
            
        return score

# Example usage
if __name__ == "__main__":
    # Demo
    config = {"thresholds": {"failed_login_attempts": 5}}
    ingestor = EnhancedLogIngestor(config)
    
    # Load from different sources
    csv_events = ingestor.load_logs({"format": "csv", "path": "datasets/cybersecurityintrusiondata.csv"})
    
    # Enrich events
    enriched = ingestor.enrich_events(csv_events[:5])  # Process first 5 for demo
    
    # Show results
    for event in enriched:
        print(f"Event: {event.get('session_id', 'unknown')} | Risk Score: {event['risk_score']}")
        if 'geo' in event:
            print(f"  Location: {event['geo']['city']}, {event['geo']['country_name']}")