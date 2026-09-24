import requests,urllib.parse,re
from bs4 import BeautifulSoup
UA={"User-Agent":"PhishGuard-AI/5.0 defensive security scanner"}
BAD=(".exe",".msi",".apk",".jar",".zip",".scr",".bat",".cmd",".ps1")

def fetch_and_analyze(url):
    ev=[]; sig={"password_fields":0,"cross_domain_form":False,"card_fields":0,"otp_fields":0,"identity_fields":0,
               "suspicious_downloads":0,"remote_lure":False,"hidden_iframes":0,"external_form_hosts":[]}
    redirects=[]; final=url; r=None
    try:
        r=requests.get(url,headers=UA,timeout=12,allow_redirects=True)
        final=r.url; redirects=[x.url for x in r.history]+[r.url]
        soup=BeautifulSoup(r.text,"html.parser"); inputs=soup.find_all("input"); forms=soup.find_all("form")
        sig["password_fields"]=sum(x.get("type","").lower()=="password" for x in inputs)
        final_host=urllib.parse.urlsplit(final).hostname or ""
        for f in forms:
            a=f.get("action","")
            if a:
                ah=urllib.parse.urlsplit(urllib.parse.urljoin(final,a)).hostname
                if ah and ah!=final_host:
                    sig["cross_domain_form"]=True; sig["external_form_hosts"].append(ah)
        def count(keys):
            return sum(any(k in ((x.get("name","")+" "+x.get("placeholder","")+" "+x.get("id","")).lower()) for k in keys) for x in inputs)
        sig["card_fields"]=count(["card","cvv","expiry","credit"])
        sig["otp_fields"]=count(["otp","one time","verification code"])
        sig["identity_fields"]=count(["aadhaar","aadhar","pan","passport","dob","ssn"])
        sig["suspicious_downloads"]=sum(urllib.parse.urlsplit(a["href"]).path.lower().endswith(BAD) for a in soup.find_all("a",href=True))
        sig["remote_lure"]=any(k in soup.get_text(" ",strip=True).lower() for k in ["anydesk","teamviewer","remote access","remote support"])
        sig["hidden_iframes"]=sum(1 for x in soup.find_all("iframe") if x.get("style") and "display:none" in x.get("style","").replace(" ","").lower())
        text=soup.get_text(" ",strip=True).lower()
        urgent=sum(k in text for k in ["urgent","verify now","account suspended","act now","limited time","security alert"])
        if urgent>=2: ev.append({"severity":"medium","message":"Multiple urgency/social-engineering phrases","points":8})
        scripts=" ".join(x.get_text(" ",strip=True) for x in soup.find_all("script"))
        if "eval(" in scripts or "fromcharcode" in scripts.lower(): ev.append({"severity":"medium","message":"JavaScript obfuscation signal","points":6})
        if sig["password_fields"]: ev.append({"severity":"medium","message":"Password field detected","points":6})
        if sig["cross_domain_form"]: ev.append({"severity":"high","message":"Cross-domain form submission","points":18})
        if sig["card_fields"] or sig["otp_fields"]: ev.append({"severity":"high","message":"Financial/OTP collection fields","points":15})
        if sig["identity_fields"]: ev.append({"severity":"high","message":"Identity information fields","points":12})
        if sig["suspicious_downloads"]: ev.append({"severity":"high","message":"Risky download links","points":18})
        if sig["remote_lure"]: ev.append({"severity":"high","message":"Remote-access lure keywords","points":15})
        if sig["hidden_iframes"]: ev.append({"severity":"low","message":"Hidden iframe detected","points":4})
        return {"evidence":ev,"signals":sig,"redirect_chain":redirects,"final_url":final,"status_code":r.status_code,
                "title":soup.title.get_text(strip=True) if soup.title else None}
    except Exception as e:
        ev.append({"severity":"info","message":"Website fetch unavailable: "+str(e)[:100],"points":0})
        return {"evidence":ev,"signals":sig,"redirect_chain":redirects,"final_url":final,"status_code":getattr(r,"status_code",None),"title":None}
