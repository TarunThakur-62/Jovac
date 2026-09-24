import re, urllib.parse, ipaddress, math
import numpy as np

FEATURE_NAMES = [
    "url_length","host_length","dot_count","hyphen_count","digit_count",
    "subdomain_count","has_https","has_ip","at_symbol","keyword_count",
    "path_length","query_length","hostname_entropy","punycode","double_slash_path",
    "port_present","fragment_length"
]
KEYWORDS = ["login","signin","verify","account","password","secure","update","confirm","wallet","bank","otp","free","auth","billing"]

def normalize(url):
    url=(url or "").strip()
    return url if re.match(r"^https?://",url,re.I) else "https://"+url

def _entropy(s):
    if not s:return 0.0
    n=len(s); return -sum((s.count(c)/n)*math.log2(s.count(c)/n) for c in set(s))

def extract_features(url):
    u=normalize(url); p=urllib.parse.urlsplit(u); host=p.hostname or ""
    try: has_ip=int(ipaddress.ip_address(host).version in (4,6))
    except ValueError: has_ip=0
    path=p.path or ""
    return np.array([[
        len(u),len(host),u.count("."),u.count("-"),sum(c.isdigit() for c in u),
        max(0,host.count(".")),int(p.scheme.lower()=="https"),has_ip,int("@" in u),
        sum(k in u.lower() for k in KEYWORDS),len(path),len(p.query),_entropy(host),
        int("xn--" in host.lower()),int("//" in path),int(p.port is not None),len(p.fragment)
    ]],dtype=float)
