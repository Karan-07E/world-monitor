import socket
import ipaddress
import urllib.parse
from typing import List, Optional

# Only allow loopback and the specific Compose subnet (e.g., 172.20.0.0/16 or similar, we use a placeholder or config)
# For the purpose of the engine, this should be configurable via env, but defaults to loopback + a strict docker network.
import os

ALLOWED_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]
compose_subnet = os.getenv("COMPOSE_SUBNET")
if compose_subnet:
    ALLOWED_SUBNETS.append(ipaddress.ip_network(compose_subnet))

BLOCKED_DOMAINS = ["worldmonitor.app"]

def is_domain_blocked(domain: str) -> bool:
    domain = domain.lower()
    for blocked in BLOCKED_DOMAINS:
        if domain == blocked or domain.endswith("." + blocked):
            return True
    return False

def resolve_and_pin_ip(url: str) -> Optional[str]:
    """
    Resolves the hostname of the given URL. 
    Validates every resolved IP against the allowed subnets.
    Returns the pinned URL with the IP instead of the hostname if valid, else raises ValueError.
    """
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: No hostname")

    if is_domain_blocked(hostname):
        raise ValueError(f"Domain {hostname} is explicitly blocked.")

    try:
        # Resolve all IPs for the hostname
        addrinfo = socket.getaddrinfo(hostname, parsed.port or 80)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    
    valid_ip = None
    for res in addrinfo:
        ip = res[4][0]
        ip_obj = ipaddress.ip_address(ip)
        
        is_allowed = False
        for subnet in ALLOWED_SUBNETS:
            if ip_obj in subnet:
                is_allowed = True
                break
        
        if not is_allowed:
            raise ValueError(f"Resolved IP {ip} is not in the allowed local/compose subnets.")
        
        # Pick the first valid IP to pin
        if not valid_ip:
            valid_ip = ip

    if not valid_ip:
        raise ValueError("No valid IP found.")

    # Reconstruct URL with pinned IP
    netloc = f"[{valid_ip}]" if ":" in valid_ip else valid_ip
    if parsed.port:
        netloc += f":{parsed.port}"
        
    pinned_url = parsed._replace(netloc=netloc).geturl()
    return pinned_url

def enforce_target_guard(target_url: str):
    """
    Enforces the target guard rules on the provided target_url.
    Returns the pinned IP URL.
    """
    return resolve_and_pin_ip(target_url)
