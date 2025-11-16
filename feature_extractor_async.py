# feature_extractor_async.py
import aiohttp
import urllib.parse

async def fetch_html(session, url):
    try:
        async with session.get(url, timeout=5, allow_redirects=True) as resp:
            return await resp.text(errors="ignore")
    except:
        return ""

def extract_basic(url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    url_l = url.lower()

    return {
        "length_url": len(url_l),
        "length_hostname": len(host),
        "nb_dots": host.count("."),
        "nb_hyphens": url_l.count("-"),
        "nb_numeric_chars": sum(c.isdigit() for c in url_l),
        "contains_scam_keyword": int(any(k in url_l for k in [
            "verify", "login", "account", "update", "secure", "confirm", "urgent"
        ])),
    }

async def extract_features(url):
    base = extract_basic(url)

    async with aiohttp.ClientSession() as session:
        await fetch_html(session, url)

    return base
