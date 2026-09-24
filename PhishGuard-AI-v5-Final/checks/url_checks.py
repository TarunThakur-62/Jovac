import urllib.parse, ipaddress, re
KEY=["login","verify","account","password","secure","update","confirm","wallet","bank","otp","auth","billing"]
SHORTENERS={"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly","buff.ly"}

def url_checks(url):
    p=urllib.parse.urlsplit(url); h=p.hostname or ""; ev=[]
    if p.scheme!="https":ev.append({"severity":"medium","message":"Not using HTTPS","points":8})
    if len(url)>90:ev.append({"severity":"medium","message":"Long URL","points":8})
    if "@" in url:ev.append({"severity":"high","message":"@ symbol in URL","points":20})
    if p.username or p.password:ev.append({"severity":"high","message":"Embedded URL credentials detected","points":25})
    try: ipaddress.ip_address(h); ev.append({"severity":"high","message":"IP address used as hostname","points":25})
    except ValueError: pass
    hits=[k for k in KEY if k in url.lower()]
    if hits:ev.append({"severity":"medium","message":"Sensitive URL tokens: "+", ".join(hits),"points":min(12,len(hits)*2)})
    if h.count(".")>=4:ev.append({"severity":"medium","message":"Excessive subdomains","points":8})
    if "xn--" in h.lower():ev.append({"severity":"medium","message":"Punycode hostname","points":8})
    if h.lower() in SHORTENERS:ev.append({"severity":"medium","message":"URL shortener detected","points":8})
    if "//" in p.path:ev.append({"severity":"medium","message":"Double-slash path obfuscation","points":6})
    return {"evidence":ev,"summary":{"host":h,"length":len(url),"keywords":hits,"scheme":p.scheme,"has_ip":bool(re.match(r"^\d+\.\d+\.\d+\.\d+$",h))}}
