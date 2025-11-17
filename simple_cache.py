# simple_cache.py
import os, json, time, hashlib, pathlib

CACHE_DIR = os.path.join("/tmp", "smellscam_cache")
pathlib.Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)

def _key(k):
    return os.path.join(CACHE_DIR, hashlib.sha256(k.encode()).hexdigest() + ".json")

def cache_get(key, max_age=3600):
    p = _key(key)
    if not os.path.exists(p):
        return None
    try:
        st = os.stat(p)
        if time.time() - st.st_mtime > max_age:
            return None
        with open(p, "r") as f:
            return json.load(f)
    except Exception:
        return None

def cache_set(key, value):
    p = _key(key)
    try:
        with open(p, "w") as f:
            json.dump(value, f)
    except Exception:
        pass
