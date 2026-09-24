import argparse
from core.ml_engine import train_and_save
if __name__=="__main__":
    p=argparse.ArgumentParser(description="Train PhishGuard-AI baseline/CSV model")
    p.add_argument("--dataset",help="CSV containing FEATURE_NAMES columns and integer label column")
    a=p.parse_args()
    print("Training complete:",train_and_save(a.dataset))
