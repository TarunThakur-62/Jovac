import socket, ssl, datetime

def dns_and_tls(host):
    ev=[];ips=[];tls={}
    try: ips=sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception as e: ev.append({"severity":"info","message":"DNS resolution unavailable","points":0})
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=6) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                cert=ss.getpeercert()
                tls={"valid":True,"notAfter":cert.get("notAfter"),"subject":str(cert.get("subject")),"issuer":str(cert.get("issuer"))}
    except Exception as e:
        tls={"valid":False,"error":str(e)[:100]}
        ev.append({"severity":"low","message":"TLS verification unavailable/failed","points":4})
    return {"evidence":ev,"ips":ips,"tls":tls}

def domain_age(host):
    try:
        import whois
        w=whois.whois(host); d=w.creation_date
        if isinstance(d,list): d=next((x for x in d if x),None)
        if d and d.tzinfo: d=d.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        age=(datetime.datetime.utcnow()-d).days if d else None
        ev=[]
        if age is not None and age<30: ev.append({"severity":"high","message":f"Recently registered domain ({age} days)","points":15})
        elif age is not None and age<90: ev.append({"severity":"medium","message":f"Young domain ({age} days)","points":7})
        return {"evidence":ev,"age_days":age}
    except Exception as e:
        return {"evidence":[{"severity":"info","message":"WHOIS/domain age unavailable","points":0}],"age_days":None}
