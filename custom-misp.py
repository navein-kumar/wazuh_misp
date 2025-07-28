#!/usr/bin/env python3
import sys
import os
import json
import re
import ipaddress
import requests
import logging
from socket import socket, AF_UNIX, SOCK_DGRAM
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIG ===
LOG_IOCS_FILE = "/var/ossec/logs/misp-iocs.log"
LOG_ALERTS_FILE = "/var/ossec/logs/misp-alerts.log"
MISP_BASE_URL = "https://cti.codesec.in/attributes/restSearch/"
MISP_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MISP_SSL_VERIFY = False
SOCKET_PATH = f"{os.path.dirname(os.path.dirname(os.path.realpath(__file__)))}/queue/sockets/queue"

# Minimal logging (only errors)
logging.basicConfig(
    filename="/var/ossec/logs/misp-integration.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

IOC_PATTERNS = {
    'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    'url': re.compile(r'https?://[\w./:%#\$&\?\(\)~\-=]+'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'filename': re.compile(r'\b[\w\-.]+\.(exe|dll|bat|ps1|sh|jar|zip|rar|7z|msi)\b', re.IGNORECASE),
    'cve': re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
}

EXCLUDED_DOMAINS = {'localhost', 'localdomain', 'local', 'example.com', 'example.org', 'test.com',
    'internal', 'corp', 'lan', '127.0.0.1', '::1'}

EXCLUDED_DOMAIN_PATTERNS = [
    r'^localhost$', r'^127\.0\.0\.1$', r'^::1$', r'.*\.cloudapp\.net$', r'.*\.compute\.internal$',
    r'.*\.amazonaws\.com$', r'.*\.internal\..*', r'.*\.corp\..*', r'.*\.lan$', r'.*\.local$'
]

EXCLUDED_FILENAMES = {'tomcat-juli.jar', 'logging.properties', 'vector.json', 'catalina.jar',
    'bootstrap.jar', 'commons-daemon.jar', 'servlet-api.jar'}

EXCLUDED_URLS = {
    'http://localhost/', 'https://localhost/', 'http://localhost', 'https://localhost',
    'http://127.0.0.1/', 'https://127.0.0.1/', 'http://127.0.0.1', 'https://127.0.0.1',
    'http://::1/', 'https://::1/', 'http://::1', 'https://::1'
}

JAVA_PROPERTY_PREFIXES = [
    'Djava.', 'Dorg.', 'Dcom.', 'Dsun.', 'Dfile.', 'Duser.', 'Dos.', 'Dpath.', 'Dline.', 'Djdk.', 'Djavax.'
]

MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def safe_get(obj, key, default=None):
    try:
        if isinstance(obj, dict):
            return obj.get(key, default)
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return obj[0].get(key, default)
    except Exception as e:
        logging.error(f"safe_get error: {e}")
    return default

def send_event(alert_data, agent=None):
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
    try:
        url = f"{MISP_BASE_URL}value:{ioc}"
        response = requests.get(url, headers=MISP_HEADERS, verify=MISP_SSL_VERIFY, timeout=10)
        return response.json()
    except Exception as e:
        logging.error(f"MISP search error for {ioc}: {e}")
        return {"misp": {"error": str(e)}}

def is_localhost_variant(value):
    value_lower = str(value).lower().strip()
    localhost_variants = {'localhost', '127.0.0.1', '::1', 'localhost.localdomain', 'localhost.', '127.0.0.1.', '::1.'}
    if value_lower in localhost_variants: return True
    if value_lower in EXCLUDED_URLS: return True
    if value_lower.startswith(('http://localhost', 'https://localhost', 'ftp://localhost')): return True
    if value_lower.startswith(('http://127.0.0.1', 'https://127.0.0.1', 'ftp://127.0.0.1')): return True
    if value_lower.startswith(('http://::1', 'https://::1', 'ftp://::1')): return True
    return False

def is_valid_ip(ip):
    if is_localhost_variant(ip): return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (ip_obj.is_global and not ip_obj.is_private and not ip_obj.is_loopback and
                not ip_obj.is_multicast and not ip_obj.is_reserved)
    except ValueError:
        return False

def is_valid_domain(domain):
    if not domain: return False
    if is_localhost_variant(domain): return False
    domain_lower = domain.lower().strip()
    if domain_lower in EXCLUDED_DOMAINS: return False
    for pattern in EXCLUDED_DOMAIN_PATTERNS:
        if re.match(pattern, domain_lower): return False
    parts = domain.split('.')
    if len(parts) < 2: return False
    tld = parts[-1].lower()
    if tld in ['local', 'localhost', 'internal', 'corp', 'lan']: return False
    return True

def is_valid_url(url):
    if not url: return False
    if is_localhost_variant(url): return False
    try:
        parsed = urlparse(url)
        if not parsed.netloc: return False
        if is_localhost_variant(parsed.netloc): return False
        hostname = parsed.netloc.lower()
        if re.match(r'^(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)', hostname): return False
        return is_valid_domain(parsed.netloc)
    except Exception:
        return False

def is_valid_filename(filename):
    filename_lower = filename.lower()
    if filename_lower in EXCLUDED_FILENAMES: return False
    return True

def is_java_property(text):
    return any(text.startswith(prefix) for prefix in JAVA_PROPERTY_PREFIXES)

def extract_iocs(text):
    iocs = []
    try:
        text_str = str(text)
        if is_java_property(text_str): return iocs
        if len(text_str.strip()) < 4: return iocs
        if is_localhost_variant(text_str): return iocs
        for key, pattern in IOC_PATTERNS.items():
            try:
                for match in pattern.findall(text_str):
                    if is_localhost_variant(match): continue
                    if key == "ipv4" and is_valid_ip(match): iocs.append(match)
                    elif key == "domain" and is_valid_domain(match): iocs.append(match)
                    elif key == "url" and is_valid_url(match): iocs.append(match)
                    elif key == "filename" and is_valid_filename(match): iocs.append(match)
                    elif key not in ["ipv4", "domain", "url", "filename"]: iocs.append(match)
            except Exception as e:
                logging.warning(f"IoC extraction error: {e}")
    except Exception as e:
        logging.warning(f"IoC extraction error: {e}")
    return iocs

def recursive_extract(obj):
    iocs = []
    try:
        if isinstance(obj, dict):
            for val in obj.values():
                iocs.extend(recursive_extract(val))
        elif isinstance(obj, list):
            for item in obj:
                iocs.extend(recursive_extract(item))
        elif isinstance(obj, (str, int, float)):
            text = str(obj)
            if len(text) > 3 and not is_java_property(text) and not is_localhost_variant(text):
                iocs.extend(extract_iocs(text))
    except Exception as e:
        logging.error(f"recursive_extract error: {e}")
    return iocs

def build_alert(misp_attr, alert):
    # Only keep the *original* alert context; don't recursively nest full_alert!
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
    if len(sys.argv) < 2:
        logging.error("Missing alert file path.")
        sys.exit(1)
    try:
        with open(sys.argv[1], 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Error reading alert JSON: {e}")
        sys.exit(1)
    alerts = data if isinstance(data, list) else [data]
    for alert in alerts:
        try:
            agent = safe_get(alert, "agent", {})
            raw_iocs = recursive_extract(alert)
            iocs = list(set([ioc for ioc in raw_iocs if not is_localhost_variant(ioc)]))
            if iocs:
                with open(LOG_IOCS_FILE, "a") as f_iocs:
                    f_iocs.write(f'{json.dumps({"Extracted IoCs": iocs, "alert_id": safe_get(alert, "id", None)})}\n')
            for ioc in iocs:
                resp = search_misp(ioc)
                attrs = resp.get("response", {}).get("Attribute", [])
                if attrs:
                    alert_data = build_alert(attrs[0], alert)
                    send_event(alert_data, agent)
                    with open(LOG_ALERTS_FILE, "a") as f_alerts:
                        f_alerts.write(f'{json.dumps(alert_data)}\n')
        except Exception as e:
            logging.error(f"Processing error: {e}")
            continue

if __name__ == "__main__":
    main()

