import requests
import socket
import ssl
import whois
import datetime
import dns.resolver
from urllib.parse import urlparse


def extract_all_features(url):
    """
    Extract both static and live features from a given URL.
    Returns a dictionary of features.
    """
    features = {}

    # Static Features
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    features['url_length'] = len(url)
    features['num_dash'] = url.count('-')
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['num_underscore'] = url.count('_')
    features['path_level'] = path.count('/')
    features['subdomain_level'] = hostname.count('.') - 1
    features['num_dots'] = url.count('.')

    # These placeholders require HTML parsing (e.g., BeautifulSoup)
    features['pct_ext_resources'] = -1  # Placeholder
    features['iframe_or_frame'] = -1    # Placeholder
    features['missing_title'] = -1      # Placeholder

    # Live Feature: SSL Check
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
                features['has_ssl'] = 1
    except Exception:
        features['has_ssl'] = 0

    # Live Feature: Quad9 DNS
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['9.9.9.9']
        resolver.resolve(hostname, 'A')
        features['is_blocked_by_quad9'] = 0
    except Exception:
        features['is_blocked_by_quad9'] = 1

    # Live Feature: Domain Age
    try:
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.datetime.now() - creation_date).days if creation_date else -1
        features['domain_age_days'] = age_days
    except Exception:
        features['domain_age_days'] = -1

    return features


# Example usage
if __name__ == '__main__':
    url = "https://example.com"
    print(extract_all_features(url))
