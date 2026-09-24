import os, json, joblib, numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from .features import extract_features, FEATURE_NAMES
BASE=os.path.dirname(os.path.dirname(__file__)); MODEL=os.path.join(BASE,"models","phishing_model.joblib"); META=os.path.join(BASE,"models","metrics.json")

def _synthetic_training():
    rng=np.random.default_rng(42); X=[]; y=[]
    for label in (0,1):
        for _ in range(1600):
            if label==0:
                row=[rng.normal(45,15),rng.normal(18,5),rng.integers(1,4),rng.integers(0,2),rng.integers(0,4),rng.integers(0,2),1,rng.integers(0,1),0,rng.integers(0,2),rng.integers(1,20),rng.integers(0,12),rng.normal(2.8,.5),0,0,0,0]
            else:
                row=[rng.normal(110,35),rng.normal(35,12),rng.integers(2,8),rng.integers(1,7),rng.integers(1,12),rng.integers(1,5),rng.integers(0,2),rng.integers(0,2),rng.integers(0,2),rng.integers(2,9),rng.integers(5,90),rng.integers(0,70),rng.normal(4,.7),rng.integers(0,2),rng.integers(0,2),rng.integers(0,2),rng.integers(0,12)]
            X.append(row); y.append(label)
    return np.asarray(X),np.asarray(y)

def train_and_save(dataset=None):
    os.makedirs(os.path.dirname(MODEL),exist_ok=True)
    # Optional validated CSV: requires label column and all FEATURE_NAMES columns.
    X,y=None,None
    if dataset and os.path.exists(dataset):
        import pandas as pd
        df=pd.read_csv(dataset)
        if "label" in df.columns and all(c in df.columns for c in FEATURE_NAMES):
            X=df[FEATURE_NAMES].astype(float).values; y=df["label"].astype(int).values
    if X is None: X,y=_synthetic_training()
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    model=GradientBoostingClassifier(random_state=42); model.fit(Xtr,ytr); pred=model.predict(Xte)
    metrics={"accuracy":float(accuracy_score(yte,pred)),"precision":float(precision_score(yte,pred,zero_division=0)),"recall":float(recall_score(yte,pred,zero_division=0)),"f1":float(f1_score(yte,pred,zero_division=0)),"features":FEATURE_NAMES,"dataset_note":"Baseline synthetic training unless a validated CSV is supplied."}
    joblib.dump({"model":model,"feature_names":FEATURE_NAMES},MODEL)
    with open(META,"w",encoding="utf8") as f: json.dump(metrics,f,indent=2)
    return metrics

def load_model():
    if os.path.exists(MODEL):
        try:
            d=joblib.load(MODEL)
            if d.get("feature_names")==FEATURE_NAMES:return d
        except Exception: pass
    return joblib.load(MODEL) if os.path.exists(MODEL) and False else (train_and_save() and joblib.load(MODEL))

def predict_url(url):
    d=load_model(); proba=d["model"].predict_proba(extract_features(url))[0]
    return {"label":"PHISHING" if int(np.argmax(proba))==1 else "LEGITIMATE","confidence":float(max(proba)*100),
            "model":"GradientBoostingClassifier","phishing_probability":float(proba[1]*100)}

def model_status():
    return "trained GradientBoosting model loaded"
