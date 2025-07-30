#!/usr/bin/env python3
import sys
import os
import json
import logging
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM
import urllib3
from urllib.parse import urlparse
import iocextract
import re
import time
import pickle
from logging.handlers import RotatingFileHandler
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIG ===
LOG_IOCS_FILE = "/var/ossec/logs/misp-iocs.log"
LOG_ALERTS_FILE = "/var/ossec/logs/misp-alerts.log"
LOG_INTEGRATION_FILE = "/var/ossec/logs/misp-integration.log"
MISP_BASE_URL = "https://cti.codesec.in/attributes/restSearch/"
MISP_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MISP_SSL_VERIFY = False
SOCKET_PATH = f"{os.path.dirname(os.path.dirname(os.path.realpath(__file__)))}" + "/queue/sockets/queue"

# === CACHE CONFIG ===
CACHE_FILE = "/var/ossec/logs/misp-cache.pkl"
CACHE_DURATION = 3 * 60 * 60  # 3 hours in seconds
cache_lock = Lock()

# === LOG ROTATION CONFIG ===
MAX_LOG_SIZE = 1024 * 1024 * 1024  # 1GB in bytes
BACKUP_COUNT = 5  # Keep 5 old log files

# Setup rotating file handlers
def setup_rotating_logger():
    """Setup logger with rotating file handlers"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Change to DEBUG for testing
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    
    # Setup main integration log with rotation
    integration_handler = RotatingFileHandler(
        LOG_INTEGRATION_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT
    )
    integration_handler.setFormatter(formatter)
    logger.addHandler(integration_handler)
    
    return logger

# Initialize rotating logger
logger = setup_rotating_logger()

MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# === SIMPLE IoC CACHE ===
class Simple_IoC_Cache:
    def __init__(self):
        self.cache = {}
        self.load_cache()
    
    def load_cache(self):
        """Load cache from disk"""
        try:
            if os.path.exists(CACHE_FILE):
                # Check if file is readable
                if not os.access(CACHE_FILE, os.R_OK):
                    logging.error(f"Cache file exists but not readable: {CACHE_FILE}")
                    self.cache = {}
                    return
                
                # Check file size
                file_size = os.path.getsize(CACHE_FILE)
                if file_size == 0:
                    logging.warning(f"Cache file is empty: {CACHE_FILE}")
                    self.cache = {}
                    return
                
                with open(CACHE_FILE, 'rb') as f:
                    self.cache = pickle.load(f)
                    
                logging.debug(f"Loaded {len(self.cache)} cached IoCs from {CACHE_FILE} ({file_size} bytes)")
            else:
                self.cache = {}
                logging.info(f"No existing cache found at {CACHE_FILE}, starting fresh")
                
        except EOFError:
            logging.error(f"Cache file corrupted (EOF): {CACHE_FILE}")
            # Backup corrupted file and start fresh
            try:
                os.rename(CACHE_FILE, f"{CACHE_FILE}.corrupted.{int(time.time())}")
                logging.info(f"Moved corrupted cache file to backup")
            except:
                pass
            self.cache = {}
        except Exception as e:
            logging.error(f"Error loading cache from {CACHE_FILE}: {e}")
            logging.error(f"Cache file permissions: {oct(os.stat(CACHE_FILE).st_mode)[-3:] if os.path.exists(CACHE_FILE) else 'N/A'}")
            self.cache = {}
    
    def save_cache(self):
        """Save cache to disk"""
        try:
            with cache_lock:
                # Ensure directory exists
                cache_dir = os.path.dirname(CACHE_FILE)
                if not os.path.exists(cache_dir):
                    os.makedirs(cache_dir, mode=0o755)
                    logging.info(f"Created cache directory: {cache_dir}")
                
                # Write to temporary file first, then rename (atomic operation)
                temp_file = CACHE_FILE + ".tmp"
                with open(temp_file, 'wb') as f:
                    pickle.dump(self.cache, f)
                
                # Atomic rename
                os.rename(temp_file, CACHE_FILE)
                
                # Set proper permissions
                os.chmod(CACHE_FILE, 0o644)
                
                logging.debug(f"Cache saved successfully to {CACHE_FILE}")
                
        except PermissionError as e:
            logging.error(f"Permission error saving cache: {e}")
            logging.error(f"Cache file location: {CACHE_FILE}")
            logging.error(f"Current user: {os.getuid()}, group: {os.getgid()}")
        except Exception as e:
            logging.error(f"Error saving cache: {e}")
            # Clean up temp file if it exists
            temp_file = CACHE_FILE + ".tmp"
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
    
    def cleanup_expired(self):
        """Remove expired entries from cache"""
        current_time = time.time()
        expired_keys = []
        
        for ioc, data in self.cache.items():
            if current_time - data['timestamp'] > CACHE_DURATION:
                expired_keys.append(ioc)
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logging.info(f"Cleaned up {len(expired_keys)} expired cache entries")
            self.save_cache()
    
    def get(self, ioc):
        """Get IoC from cache if not expired"""
        self.cleanup_expired()
        
        if ioc in self.cache:
            data = self.cache[ioc]
            if time.time() - data['timestamp'] <= CACHE_DURATION:
                logging.info(f"Cache HIT for IoC: {ioc}")
                return data['result']
        
        logging.debug(f"Cache MISS for IoC: {ioc}")
        return None
    
    def set(self, ioc, result):
        """Add IoC result to cache"""
        with cache_lock:
            self.cache[ioc] = {
                'timestamp': time.time(),
                'result': result
            }
            self.save_cache()
        logging.debug(f"Cached result for IoC: {ioc}")

# Initialize global cache
ioc_cache = Simple_IoC_Cache()

# === ENHANCED FILTERING PATTERNS ===
IGNORED_IOC_PATTERNS = [
    r"^\d{1,4}$",  # Simple numbers
    r"^\d{7,10}$", # Numbers with 7 to 10 digits
    r"^\d{9,}$", # Longer numbers
    r"^:\d{2}:\d{2}$", # Time strings like ":07:17"
    r"^(?:0\.0\.0\.0|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$", # 0.0.0.0 and 127.0.0.0/8
    
    # Phone number patterns
    r"^\d{3}-\d{4}$", # Matches patterns like "991-4490"
    r"^\d{3}-\d{3}-\d{4}$", # Full phone numbers
    r"^\(\d{3}\)\s?\d{3}-\d{4}$", # Formatted phone numbers
    
    # MAC address patterns
    r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", # Standard MAC format
    r"^([0-9a-fA-F]{2}[.]){5}[0-9a-fA-F]{2}$", # MAC with dots
    r"^[0-9a-fA-F]{12}$", # MAC without separators
    
    # Common internal identifiers
    r"^\d{1,3}-\d{1,4}$", # Patterns like "274-1025"
    r"^\d{1,4}-\d{1,3}$", # Reverse patterns
    
    # UUID patterns
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    
    # Very short hex strings
    r"^[0-9a-fA-F]{1,8}$", # Short hex strings
]

IGNORED_EXACT_IOCS = [
    "127.0.0.1",
    "0.0.0.0",
    "localhost",
]

def setup_log_rotation(log_file):
    """Setup log rotation for IoC and alert logs"""
    try:
        # Check if log file exceeds 1GB
        if os.path.exists(log_file) and os.path.getsize(log_file) > MAX_LOG_SIZE:
            # Rotate the file
            for i in range(BACKUP_COUNT - 1, 0, -1):
                old_file = f"{log_file}.{i}"
                new_file = f"{log_file}.{i + 1}"
                if os.path.exists(old_file):
                    if i == BACKUP_COUNT - 1:
                        os.remove(old_file)  # Delete oldest file
                    else:
                        os.rename(old_file, new_file)
            
            # Move current log to .1
            os.rename(log_file, f"{log_file}.1")
            logging.info(f"Rotated log file: {log_file}")
    except Exception as e:
        logging.error(f"Error rotating log {log_file}: {e}")

def is_private_ip(ip):
    """Check if IP is in private address space"""
    private_ip_patterns = [
        re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$"),
        re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$")
    ]
    for pattern in private_ip_patterns:
        if pattern.match(ip):
            return True
    return False

def is_valid_hash(ioc):
    """Check if the IoC looks like a valid hash"""
    hash_patterns = [
        r"^[a-fA-F0-9]{32}$",  # MD5
        r"^[a-fA-F0-9]{40}$",  # SHA1  
        r"^[a-fA-F0-9]{64}$",  # SHA256
        r"^[a-fA-F0-9]{128}$", # SHA512
    ]
    for pattern in hash_patterns:
        if re.match(pattern, ioc):
            return True
    return False

def is_valid_ip(ioc):
    """Check if the IoC looks like a valid IP address"""
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, ioc):
        try:
            parts = ioc.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    return False

def is_valid_domain(ioc):
    """Check if the IoC looks like a valid domain"""
    domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    if re.match(domain_pattern, ioc):
        return '.' in ioc and not ioc.replace('.', '').isdigit()
    return False

def is_valid_url(ioc):
    """Check if the IoC looks like a valid URL"""
    url_patterns = [
        r"^https?://[^\s/$.?#].[^\s]*$",
        r"^ftp://[^\s/$.?#].[^\s]*$"
    ]
    for pattern in url_patterns:
        if re.match(pattern, ioc, re.IGNORECASE):
            return True
    return False

def safe_get(obj, key, default=None):
    """Safely get value from dict or list"""
    try:
        if isinstance(obj, dict):
            return obj.get(key, default)
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return obj[0].get(key, default)
    except Exception as e:
        logging.error(f"safe_get error: {e}")
    return default

def send_event(alert_data, agent=None):
    """Send event to OSSEC via socket"""
    try:
        agent_id = safe_get(agent, "id", "000")
        agent_name = safe_get(agent, "name", "unknown")
        agent_ip = safe_get(agent, "ip", "any")
        msg = json.dumps(alert_data)
        if agent_id == "000":
            payload = f'1:misp:{msg}'
        else:
            payload = f'1:[{agent_id}] ({agent_name}) {agent_ip}->misp:{msg}'
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_PATH)
        sock.send(payload.encode())
        sock.close()
    except Exception as e:
        logging.error(f"send_event error: {e}")

def search_misp(ioc):
    """Search MISP for IoC with simple caching"""
    # Check cache first
    cached_result = ioc_cache.get(ioc)
    if cached_result is not None:
        logging.info(f"Using cached result for IoC: {ioc}")
        return cached_result
    
    # Not in cache, make API call
    try:
        url = f"{MISP_BASE_URL}value:{ioc}"
        response = requests.get(url, headers=MISP_HEADERS, verify=MISP_SSL_VERIFY, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        # Cache the result
        ioc_cache.set(ioc, result)
        logging.info(f"MISP API call made and cached for IoC: {ioc}")
        return result
        
    except requests.exceptions.RequestException as e:
        error_result = {"misp": {"error": str(e), "status_code": getattr(e.response, 'status_code', 'N/A')}}
        logging.error(f"MISP API request error for {ioc}: {e}")
        # Don't cache errors
        return error_result
    except Exception as e:
        error_result = {"misp": {"error": str(e)}}
        logging.error(f"MISP search error for {ioc}: {e}")
        return error_result

def extract_and_filter_iocs(text):
    """Enhanced IoC extraction with comprehensive filtering"""
    try:
        raw_iocs = list(iocextract.extract_iocs(text, refang=True))
    except Exception as e:
        logging.error(f"Error extracting IoCs: {e}")
        return []
    
    filtered_iocs = set()

    for ioc in raw_iocs:
        # Skip empty or None values
        if not ioc or not str(ioc).strip():
            continue
            
        ioc = str(ioc).strip()

        # Check against exact ignored IOCs
        if ioc in IGNORED_EXACT_IOCS:
            logging.debug(f"Filtered (exact match): {ioc}")
            continue

        # Check against all defined patterns
        is_false_positive = False
        for pattern in IGNORED_IOC_PATTERNS:
            try:
                if re.match(pattern, ioc):
                    is_false_positive = True
                    logging.debug(f"Filtered (pattern match): {ioc}")
                    break
            except re.error as e:
                logging.error(f"Regex error with pattern {pattern}: {e}")
                continue
        
        if is_false_positive:
            continue

        # Check for private IP addresses
        try:
            if is_valid_ip(ioc) and is_private_ip(ioc):
                logging.debug(f"Filtered (private IP): {ioc}")
                continue
        except Exception as e:
            logging.debug(f"Error checking IP {ioc}: {e}")

        # Additional filtering for short digit strings
        if ioc.isdigit() and len(ioc) < 5:
            logging.debug(f"Filtered (short digit string): {ioc}")
            continue

        # Filter common port numbers
        if ioc.isdigit():
            try:
                port_num = int(ioc)
                if 0 < port_num < 65536:
                    common_ports = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 137, 138, 139, 143, 161, 162, 389, 443, 445, 993, 995, 3389, 8080, 8443}
                    if port_num in common_ports:
                        logging.debug(f"Filtered (common port number): {ioc}")
                        continue
            except ValueError:
                pass

        # Keep only IoCs that look like legitimate threat indicators
        should_keep = False
        
        if is_valid_hash(ioc):
            should_keep = True
            logging.debug(f"Kept IoC (hash): {ioc}")
        elif is_valid_ip(ioc) and not is_private_ip(ioc):
            should_keep = True
            logging.debug(f"Kept IoC (public IP): {ioc}")
        elif is_valid_url(ioc):
            should_keep = True
            logging.debug(f"Kept IoC (URL): {ioc}")
        elif is_valid_domain(ioc):
            should_keep = True
            logging.debug(f"Kept IoC (domain): {ioc}")
        elif ('\\' in ioc or '/' in ioc) and len(ioc) > 10:
            should_keep = True
            logging.debug(f"Kept IoC (file path): {ioc}")
        elif '@' in ioc and is_valid_domain(ioc.split('@')[-1]):
            should_keep = True
            logging.debug(f"Kept IoC (email): {ioc}")

        if should_keep:
            filtered_iocs.add(ioc)

    return list(filtered_iocs)

def build_alert(misp_attr, alert):
    """Build alert data structure"""
    orig_alert = alert.get('full_alert', alert)
    data = {
        "misp": {
            "event_id": misp_attr.get("event_id"),
            "category": misp_attr.get("category"),
            "type": misp_attr.get("type"),
            "value": misp_attr.get("value")
        },
        "full_alert": orig_alert
    }
    if "rule" in orig_alert:
        data["original_rule"] = {
            "id": safe_get(orig_alert["rule"], "id"),
            "description": safe_get(orig_alert["rule"], "description")
        }
    if "agent" in orig_alert:
        data["original_agent"] = {
            "id": safe_get(orig_alert["agent"], "id"),
            "name": safe_get(orig_alert["agent"], "name"),
            "ip": safe_get(orig_alert["agent"], "ip")
        }
    return data

def main():
    """Main function - simple sequential processing with cache"""
    if len(sys.argv) < 2:
        logging.error("Missing alert file path.")
        sys.exit(1)
    
    alert_file = sys.argv[1]
    
    # Check if alert file exists and is not empty
    if not os.path.exists(alert_file):
        logging.debug(f"Alert file does not exist: {alert_file}")
        sys.exit(0)
    
    if os.path.getsize(alert_file) == 0:
        logging.debug(f"Alert file is empty: {alert_file}")
        sys.exit(0)
    
    try:
        with open(alert_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Error reading alert JSON: {e}")
        sys.exit(1)

    alerts = data if isinstance(data, list) else [data]
    
    # Skip processing if no real alert data
    if not alerts or (len(alerts) == 1 and not alerts[0]):
        logging.debug("No valid alerts to process")
        sys.exit(0)

    # Only load cache when we have real alerts to process
    if not hasattr(ioc_cache, 'cache_loaded'):
        ioc_cache.cleanup_expired()
        ioc_cache.cache_loaded = True
        logging.debug(f"Cache initialized with {len(ioc_cache.cache)} cached IoCs")

    for alert in alerts:
        try:
            agent = safe_get(alert, "agent", {})
            text_blob = json.dumps(alert, default=str)

            # Use the enhanced filtered extraction function
            iocs = extract_and_filter_iocs(text_blob)

            # Log extracted IoCs only if some are found
            if iocs:
                # Check log rotation before writing
                setup_log_rotation(LOG_IOCS_FILE)
                
                with open(LOG_IOCS_FILE, "a") as f_iocs:
                    f_iocs.write(f'{json.dumps({"Extracted IoCs": iocs, "alert_id": safe_get(alert, "id", None), "timestamp": time.time()})}\n')
                logging.info(f"Extracted {len(iocs)} IoCs from alert {safe_get(alert, 'id', 'unknown')}: {iocs}")
            else:
                # Only log if DEBUG level - most alerts have no valid IoCs
                logging.debug(f"No valid IoCs found in alert {safe_get(alert, 'id', 'unknown')}")

            # Search MISP for each IoC (one by one, with cache)
            for ioc in iocs:
                try:
                    resp = search_misp(ioc)
                    attrs = resp.get("response", {}).get("Attribute", [])
                    
                    if attrs:
                        # IoC found in MISP - create alert
                        alert_data = build_alert(attrs[0], alert)
                        send_event(alert_data, agent)
                        
                        # Check log rotation before writing
                        setup_log_rotation(LOG_ALERTS_FILE)
                        
                        # Log the MISP match
                        with open(LOG_ALERTS_FILE, "a") as f_alerts:
                            f_alerts.write(f'{json.dumps(alert_data)}\n')
                        
                        logging.warning(f"MISP match found for IoC: {ioc} in event {attrs[0].get('event_id', 'unknown')}")
                    else:
                        logging.debug(f"No MISP match found for IoC: {ioc}")
                        
                except Exception as e:
                    logging.error(f"Error processing IoC {ioc}: {e}")
                    continue
                    
        except Exception as e:
            logging.error(f"Processing error for alert: {e}")
            continue

if __name__ == "__main__":
    main()
