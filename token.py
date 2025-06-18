import hashlib
import json
import uuid
import platform
from datetime import datetime

def generate_device_fingerprint():
    """Generate a unique fingerprint for the device"""
    device_info = {
        'platform': platform.platform(),
        'processor': platform.processor(),
        'machine': platform.machine(),
        'mac_address': hex(uuid.getnode()),
        'system': platform.system(),
        'release': platform.release(),
        'timestamp': str(datetime.now().timestamp())
    }
    
    fingerprint_str = json.dumps(device_info, sort_keys=True)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def verify_device(username, device_fingerprint):
    """Check if device is recognized for this user"""
    try:
        with open('data/users.json', 'r') as f:
            users = json.load(f)
        
        user = next((u for u in users if u.get('username') == username), None)
        return user and device_fingerprint in user.get('devices', [])
    except (FileNotFoundError, json.JSONDecodeError):
        return False