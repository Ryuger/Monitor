import json
import os
import logging
from datetime import datetime
from functools import wraps
from flask import request, render_template, g

class IPFilter:
    def __init__(self):
        self.whitelist_file = 'config/whitelist.json'
        self.blacklist_file = 'config/blacklist.json'
        self.attempts_file = 'config/attempts.json'
        self.max_attempts = 3
        
    def load_whitelist(self):
        """Load whitelist from JSON file"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    return data.get('allowed_ips', [])
        except Exception as e:
            logging.error(f"Error loading whitelist: {e}")
        return []
    
    def load_blacklist(self):
        """Load blacklist from JSON file"""
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
                    return data.get('blocked_ips', [])
        except Exception as e:
            logging.error(f"Error loading blacklist: {e}")
        return []
    
    def save_blacklist(self, blacklist):
        """Save blacklist to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.blacklist_file), exist_ok=True)
            with open(self.blacklist_file, 'w') as f:
                json.dump({'blocked_ips': blacklist}, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving blacklist: {e}")
    
    def load_attempts(self):
        """Load attempt counter from JSON file"""
        try:
            if os.path.exists(self.attempts_file):
                with open(self.attempts_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading attempts: {e}")
        return {}
    
    def save_attempts(self, attempts):
        """Save attempt counter to JSON file"""
        try:
            os.makedirs(os.path.dirname(self.attempts_file), exist_ok=True)
            with open(self.attempts_file, 'w') as f:
                json.dump(attempts, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving attempts: {e}")
    
    def get_client_ip(self):
        """Get client IP address, handling proxies"""
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr
    
    def is_ip_allowed(self, ip):
        """Check if IP is in whitelist"""
        whitelist = self.load_whitelist()
        return ip in whitelist or ip == '127.0.0.1' or ip == 'localhost'
    
    def is_ip_blocked(self, ip):
        """Check if IP is in blacklist JSON file"""
        blacklist = self.load_blacklist()
        return ip in blacklist
    
    def record_attempt(self, ip):
        """Record unauthorized attempt and block if limit exceeded"""
        attempts = self.load_attempts()
        
        if ip not in attempts:
            attempts[ip] = {
                'count': 1,
                'first_attempt': datetime.now().isoformat(),
                'last_attempt': datetime.now().isoformat()
            }
        else:
            attempts[ip]['count'] += 1
            attempts[ip]['last_attempt'] = datetime.now().isoformat()
        
        self.save_attempts(attempts)
        
        # If max attempts reached, add to blacklist
        if attempts[ip]['count'] >= self.max_attempts:
            blacklist = self.load_blacklist()
            if ip not in blacklist:
                blacklist.append(ip)
                self.save_blacklist(blacklist)
                logging.warning(f"IP blocked after {self.max_attempts} attempts: {ip}")
                return True  # Blocked
        
        logging.warning(f"Unauthorized attempt {attempts[ip]['count']}/{self.max_attempts}: {ip}")
        return False  # Not blocked yet
    
    def get_attempts_left(self, ip):
        """Get remaining attempts for IP"""
        attempts = self.load_attempts()
        if ip in attempts:
            return max(0, self.max_attempts - attempts[ip]['count'])
        return self.max_attempts
    
    def log_access_attempt(self, ip, status='blocked'):
        """Log access attempt (simplified)"""
        if status == 'blocked':
            logging.warning(f"Blocked IP access attempt: {ip} - Path: {request.path}")
        elif status == 'unauthorized':
            logging.warning(f"Unauthorized IP access attempt: {ip} - Path: {request.path}")
        else:
            logging.info(f"Allowed IP access: {ip} - Path: {request.path}")
    
    def check_ip_access(self):
        """Main IP checking function with attempt counter"""
        ip = self.get_client_ip()
        g.client_ip = ip
        
        # First check whitelist - if in whitelist, always allow
        if self.is_ip_allowed(ip):
            self.log_access_attempt(ip, 'allowed')
            return True, "allowed"
        
        # Then check blacklist - if blocked, ignore completely
        if self.is_ip_blocked(ip):
            self.log_access_attempt(ip, 'blocked')
            return False, "blocked"
        
        # If not in whitelist and not blocked, count attempts
        blocked = self.record_attempt(ip)
        if blocked:
            return False, "blocked"
        else:
            return False, "unauthorized"

ip_filter = IPFilter()

def require_ip_whitelist(f):
    """Decorator to check IP whitelist with attempt counter"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed, status = ip_filter.check_ip_access()
        
        if not allowed:
            if status == "blocked":
                # Completely ignore blocked IPs (no response)
                return "", 204
            else:
                # Show error page for unauthorized IPs with attempts left
                attempts_left = ip_filter.get_attempts_left(g.client_ip)
                return render_template("blocked.html", 
                                     ip=g.client_ip,
                                     attempts_left=attempts_left), 403
        
        return f(*args, **kwargs)
    return decorated_function
