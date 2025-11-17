import urllib.parse
import re
import requests


# -------------------------------------------------------
# Safe lightweight HTML request (used for shopping filter)
# -------------------------------------------------------
def safe_request(url, timeout=5, max_bytes=200000):
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (SmellScam-Bot)"},
            stream=True
        )
        content = b""
        for chunk in r.iter_content(4096):
            content += chunk
            if len(content) > max_bytes:
                break
        return content.decode(errors="ignore")
    except:
        return ""


# -------------------------------------------------------
# Extract minimal lexical features (fast)
# -------------------------------------------------------
def extract_all_features(url):
    u = url.strip()
    parsed = urllib.parse.urlparse(u)
    host = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    return {
        "length_url": len(u),
        "length_hostname": len(host),
        "nb_dots": host.count("."),
        "nb_hyphens": host.count("-"),
        "nb_numeric_chars": sum(c.isdigit() for c in u),

        "contains_scam_keyword": int(any(k in u.lower() for k in [
            "login","verify","secure","account","update","urgent","confirm","gift"
        ])),

        "has_query": int(bool(query)),
        "has_www": int(host.startswith("www")),
        "https": int(parsed.scheme == "https"),

        # Shopping classifier will fill these
        "vt_total_vendors": 0,
        "vt_malicious_count": 0,
        "vt_detection_ratio": 0.0,
    }
