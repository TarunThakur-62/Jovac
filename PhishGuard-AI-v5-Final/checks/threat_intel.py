import os,requests
def check_threat_intelligence(url):
 out={"VirusTotal":"NOT CONFIGURED","Google Safe Browsing":"NOT CONFIGURED","evidence":[]}
 vt=os.getenv("VT_API_KEY")
 if vt:
  try:
   r=requests.post("https://www.virustotal.com/api/v3/urls",headers={"x-apikey":vt},data={"url":url},timeout=15)
   out["VirusTotal"]="SUBMITTED / API RESPONSE "+str(r.status_code)
  except Exception as e:out["VirusTotal"]="ERROR: "+str(e)[:80]
 g=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
 if g:
  try:
   body={"client":{"clientId":"phishguard-ai","clientVersion":"4.0"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}}
   r=requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+g,json=body,timeout=15)
   out["Google Safe Browsing"]="MATCH FOUND" if r.json().get("matches") else "NO MATCH RETURNED"
  except Exception as e:out["Google Safe Browsing"]="ERROR: "+str(e)[:80]
 return out
