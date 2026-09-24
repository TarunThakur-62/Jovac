import difflib, json, os, urllib.parse

BASE=os.path.dirname(os.path.dirname(__file__))
with open(os.path.join(BASE,"data","official_domains.json"),encoding="utf8") as f:
    OFFICIAL=json.load(f)

def _registrable(host):
    parts=(host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts)>=2 else (parts[0] if parts else "")

def brand_checks(host):
    host=(host or "").lower().strip(".")
    base=_registrable(host); ev=[]; matches=[]; verified=[]
    for brand,domains in OFFICIAL.items():
        exact=any(host==d or host.endswith("."+d) for d in domains)
        if exact:
            verified.append(brand)
            continue
        labels=host.replace("-","").split(".")
        ratio=max((difflib.SequenceMatcher(None,x,brand).ratio() for x in labels),default=0)
        token=brand in host.replace("-","")
        if token or ratio>=0.82:
            matches.append({"brand":brand,"similarity":round(ratio*100,1),"official_domain_match":False})
            ev.append({"severity":"high","message":f"Possible {brand.upper()} impersonation: non-official domain","points":15})
    if verified:
        ev.append({"severity":"info","message":"Official brand domain verified: "+", ".join(verified),"points":-8})
    return {"evidence":ev,"matches":matches,"official_matches":verified,"registrable_domain":base}
