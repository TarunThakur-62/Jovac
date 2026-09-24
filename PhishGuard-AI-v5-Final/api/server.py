from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.analyzer import analyze_target
app=FastAPI(title="PhishGuard-AI v5 API",version="5.0")
class ScanRequest(BaseModel): url:str
@app.get("/health")
def health(): return {"status":"ok","service":"PhishGuard-AI v5"}
@app.post("/scan")
def scan(req:ScanRequest):
    if not req.url.strip(): raise HTTPException(400,"URL required")
    return analyze_target(req.url)
