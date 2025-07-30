#!/usr/bin/env python3
import sys
import os
import json
import logging
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM
import urllib3
import iocextract
import re
from logging.handlers import RotatingFileHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIG ===
LOG_IOCS_FILE = "/var/ossec/logs/misp-iocs.log"
LOG_ALERTS_FILE = "/var/ossec/logs/misp-alerts.log"
LOG_INTEGRATION_FILE = "/var/ossec/logs/misp-integration.log"
MISP_BASE_URL = "https://cti.codesec.in/attributes/restSearch/"
MISP_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MISP_SSL_VERIFY = False
SOCKET_PATH = f"{os.path.dirname(os.path.dirname(os.path.realpath(__file__)))}" + "/queue/sockets/queue"

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
    "134.0.0.0",
    "169.254.169.254",
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
    """Search MISP for IoC - process all responses"""
    try:
        url = f"{MISP_BASE_URL}value:{ioc}"
        response = requests.get(url, headers=MISP_HEADERS, verify=MISP_SSL_VERIFY, timeout=30)
        response.raise_for_status()
        
        # Log response size for monitoring
        content_length = response.headers.get('content-length')
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)
            logging.info(f"MISP response size: {size_mb:.1f}MB for IoC: {ioc}")
        
        # Process ALL responses regardless of size
        result = response.json()
        logging.info(f"MISP API call completed for IoC: {ioc}")
        return result
        
    except requests.exceptions.Timeout:
        logging.error(f"MISP API timeout (30s) for IoC: {ioc}")
        return {"misp": {"error": "timeout"}}
    except requests.exceptions.RequestException as e:
        logging.error(f"MISP API request error for {ioc}: {e}")
        return {"misp": {"error": str(e), "status_code": getattr(e.response, 'status_code', 'N/A')}}
    except Exception as e:
        logging.error(f"MISP search error for {ioc}: {e}")
        return {"misp": {"error": str(e)}}

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

        # Filter network addresses (XXX.0.0.0 pattern)
        if re.match(r"^\d{1,3}\.0\.0\.0$", ioc):
            logging.debug(f"Filtered (network address): {ioc}")
            continue

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
    """Main function - simple processing without cache"""
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

    for alert in alerts:
        try:
            agent = safe_get(alert, "agent", {})
            text_blob = json.dumps(alert, default=str)

            # Extract and filter IoCs
            iocs = extract_and_filter_iocs(text_blob)

            # Log extracted IoCs only if some are found
            if iocs:
                # Check log rotation before writing
                setup_log_rotation(LOG_IOCS_FILE)
                
                with open(LOG_IOCS_FILE, "a") as f_iocs:
                    f_iocs.write(f'{json.dumps({"Extracted IoCs": iocs, "alert_id": safe_get(alert, "id", None)})}\n')
                logging.info(f"Extracted {len(iocs)} IoCs from alert {safe_get(alert, 'id', 'unknown')}: {iocs}")
            else:
                logging.debug(f"No valid IoCs found in alert {safe_get(alert, 'id', 'unknown')}")

            # Search MISP for each IoC (simple one by one)
            for ioc in iocs:
                try:
                    resp = search_misp(ioc)
                    
                    # Handle MISP response safely
                    if isinstance(resp, dict) and "response" in resp:
                        attrs = resp.get("response", {}).get("Attribute", [])
                        
                        # Ensure attrs is a list and has items
                        if attrs and isinstance(attrs, list) and len(attrs) > 0:
                            # Use first attribute for alert
                            first_attr = attrs[0]
                            if isinstance(first_attr, dict):
                                # IoC found in MISP - create alert
                                alert_data = build_alert(first_attr, alert)
                                send_event(alert_data, agent)
                                
                                # Check log rotation before writing
                                setup_log_rotation(LOG_ALERTS_FILE)
                                
                                # Log the MISP match
                                with open(LOG_ALERTS_FILE, "a") as f_alerts:
                                    f_alerts.write(f'{json.dumps(alert_data)}\n')
                                
                                logging.warning(f"MISP match found for IoC: {ioc} in event {first_attr.get('event_id', 'unknown')}")
                            else:
                                logging.debug(f"Invalid attribute format for IoC: {ioc}")
                        else:
                            logging.debug(f"No MISP match found for IoC: {ioc}")
                    else:
                        # Handle error responses
                        if isinstance(resp, dict) and "misp" in resp and "error" in resp["misp"]:
                            logging.debug(f"MISP error for IoC {ioc}: {resp['misp']['error']}")
                        else:
                            logging.debug(f"Unexpected MISP response format for IoC: {ioc}")
                        
                except Exception as e:
                    logging.error(f"Error processing IoC {ioc}: {e}")
                    continue
                    
        except Exception as e:
            logging.error(f"Processing error for alert: {e}")
            continue

if __name__ == "__main__":
    main()
