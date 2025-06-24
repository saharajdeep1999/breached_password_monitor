import requests
import hashlib
import time
from database import MonitoredPassword
from datetime import datetime

class HIBPClient:
    def __init__(self, config):
        self.api_url = config['hibp']['api_url']
        self.rate_limit = config['hibp']['rate_limit']
    
    def check_password(self, password):
        """Check a single password against HIBP"""
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        return self.check_hash(prefix, suffix)
    
    def check_hash(self, prefix, suffix):
        """Check password hash against HIBP"""
        try:
            response = requests.get(f"{self.api_url}{prefix}", timeout=5)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return int(count)
            return 0
        except Exception as e:
            print(f"HIBP API error: {e}")
            return -1
        finally:
            time.sleep(self.rate_limit)
    
    def batch_check(self, session):
        """Check all monitored passwords"""
        results = []
        passwords = session.query(MonitoredPassword).filter_by(is_active=1).all()
        
        for pwd in passwords:
            count = self.check_hash(pwd.sha1_prefix, pwd.sha1_suffix)
            if count > pwd.breach_count:
                results.append({
                    "id": pwd.id,
                    "alias": pwd.alias,
                    "previous_count": pwd.breach_count,
                    "new_count": count,
                    "breached": count > 0
                })
                pwd.breach_count = count
                pwd.last_checked = datetime.now()
        
        session.commit()
        return results
