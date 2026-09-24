import os,json,datetime
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib.styles import getSampleStyleSheet
BASE=os.path.dirname(os.path.dirname(__file__)); OUT=os.path.join(BASE,"reports","output"); os.makedirs(OUT,exist_ok=True)
def generate_reports(r):
    stamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); r["report_id"]=stamp
    paths={k:os.path.join(OUT,f"scan_{stamp}.{ext}") for k,ext in [("json","json"),("txt","txt"),("pdf","pdf")]}
    with open(paths["json"],"w",encoding="utf8") as f: json.dump(r,f,indent=2,default=str)
    lines=["PHISHGUARD-AI v5.0 SECURITY REPORT","Target: "+r["target"],"Risk Score: "+str(r["risk_score"])+"/100","Verdict: "+r["verdict"],
           "ML: "+r["ml"]["label"]+" ("+str(round(r["ml"]["confidence"],2))+"%)","Likely Purpose: "+r["intent"]["likely_purpose"],"","EVIDENCE:"]
    lines += [f"[{e.get('severity','info').upper()}] {e.get('message','')}" for e in r.get("evidence",[])]
    with open(paths["txt"],"w",encoding="utf8") as f:f.write("\n".join(lines))
    st=getSampleStyleSheet(); story=[Paragraph("PhishGuard-AI v5.0 Security Report",st["Title"]),Spacer(1,12)]
    for x in lines: story += [Paragraph(escape(x),st["BodyText"]),Spacer(1,5)]
    SimpleDocTemplate(paths["pdf"],pagesize=A4).build(story)
    with open(os.path.join(OUT,"history.jsonl"),"a",encoding="utf8") as f:
        f.write(json.dumps({"time":r["scan_time"],"target":r["target"],"score":r["risk_score"],"verdict":r["verdict"]})+"\n")
    return paths
def list_reports():
    fs=sorted(x for x in os.listdir(OUT) if x.endswith((".pdf",".txt",".json")))
    return "\n".join(fs) if fs else "No reports available."
