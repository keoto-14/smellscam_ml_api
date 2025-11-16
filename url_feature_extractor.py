import urllib.parse

def extract_all_features(url):
    url_l = url.lower()
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc

    return {
        "length_url": len(url),
        "length_hostname": len(host),
        "nb_dots": host.count("."),
        "nb_hyphens": host.count("-"),
        "nb_numeric_chars": sum(c.isdigit() for c in url),
        "contains_scam_keyword": int(any(k in url_l for k in [
            "login", "verify", "secure", "bank", "account",
            "update", "confirm", "urgent", "pay", "gift", "free"
        ])),
    }
