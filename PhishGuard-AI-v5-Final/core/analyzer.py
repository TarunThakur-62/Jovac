import datetime, urllib.parse
from checks.url_checks import url_checks
from checks.brand_checks import brand_checks
from checks.network_checks import dns_and_tls, domain_age
from checks.content_checks import fetch_and_analyze
from checks.threat_intel import check_threat_intelligence
from core.ml_engine import predict_url
from core.intent import classify_intent
from core.risk_engine import calculate_risk

def analyze_target(url,console=None,agent=None):
    if "://" not in url:url="https://"+url
    p=urllib.parse.urlsplit(url); host=p.hostname or ""
    if console: console.print("[green][✓] URL structure analyzed[/green]")
    u=url_checks(url)
    if console: console.print("[green][✓] DNS lookup completed[/green]")
    n=dns_and_tls(host)
    if console: console.print("[green][✓] SSL certificate checked[/green]")
    if console: console.print("[green][✓] WHOIS/domain intelligence checked[/green]")
    age=domain_age(host)
    b=brand_checks(host)
    if console: console.print("[green][✓] Official-domain/brand verification checked[/green]")
    c=fetch_and_analyze(url)
    if console: console.print("[green][✓] Website content & behaviour analyzed[/green]")
    ml=predict_url(url)
    if console: console.print("[green][✓] ML prediction completed[/green]")
    ti=check_threat_intelligence(url)
    if console: console.print("[green][✓] Threat intelligence checked[/green]")
    ev=u["evidence"]+n["evidence"]+age["evidence"]+b["evidence"]+c["evidence"]
    official=bool(b.get("official_matches"))
    ti_hit=any("MATCH" in str(v).upper() for k,v in ti.items() if k!="evidence")
    score,verdict=calculate_risk(ev,ml["phishing_probability"],age.get("age_days"),official,ti_hit)
    result={"scan_time":datetime.datetime.now().isoformat(),"target":url,"host":host,"url_checks":u,"network":n,"domain_age":age,
            "brand":b,"content":c,"ml":ml,"threat_intelligence":ti,"risk_score":score,"verdict":verdict,
            "intent":classify_intent(c["signals"]),"evidence":ev,
            "confidence":"HIGH" if score>=70 else ("MEDIUM" if score>=35 else "LOW")}
    if agent: result["agent"]={"mode":"autonomous-defensive","modules_executed":["URL","DNS/TLS","WHOIS","Brand","Website","ML","Threat Intelligence","Risk Engine"]}
    return result
